{-# Language PatternGuards, RecordWildCards, ScopedTypeVariables #-}
module System.CredentialStore.DBusSecretService
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import Control.Exception.Safe
import Control.Monad
import Crypto.Cipher.AES
import Crypto.Cipher.Types
import Crypto.Data.Padding
import Crypto.Error
import Crypto.Hash
import Crypto.KDF.HKDF
import Crypto.PubKey.DH
import Crypto.Random
import DBus
import DBus.Client
import Data.Bits
import Data.ByteArray
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as M

-- |Abstract context for credential store communications.
data CredentialStore = CredentialStore
    { csClient :: Client
    , csSession :: ObjectPath
    , csCipher :: AES128
    }

type CredentialObject = (ObjectPath, BS.ByteString, BS.ByteString, String)

noObject :: ObjectPath
noObject = objectPath_ "/"

destination :: BusName
destination = busName_ "org.freedesktop.secrets"

servicePath :: ObjectPath
servicePath = objectPath_ "/org/freedesktop/secrets"

serviceInterface :: InterfaceName
serviceInterface = interfaceName_ "org.freedesktop.Secret.Service"

openSession :: MemberName
openSession = memberName_ "OpenSession"

unlock :: MemberName
unlock = memberName_ "Unlock"

defaultCollection :: ObjectPath
defaultCollection = objectPath_ "/org/freedesktop/secrets/aliases/default"

collectionInterface :: InterfaceName
collectionInterface = interfaceName_ "org.freedesktop.Secret.Collection"

createItem :: MemberName
createItem = memberName_ "CreateItem"

searchItems :: MemberName
searchItems = memberName_ "SearchItems"

itemInterface :: InterfaceName
itemInterface = interfaceName_ "org.freedesktop.Secret.Item"

getSecret :: MemberName
getSecret = memberName_ "GetSecret"

delete :: MemberName
delete = memberName_ "Delete"

serviceCall :: ObjectPath -> InterfaceName -> MemberName -> MethodCall
serviceCall o i m = (methodCall o i m) { methodCallDestination = Just destination }

dhPrime :: Integer
dhPrime = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF

dhParams :: Params
dhParams = Params
    { params_p = dhPrime
    , params_g = 2
    , params_bits = 1024
    }

-- |Open credential store and execute function passing it as parameter.
-- Store is closed even in presence of exceptions.
withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore = bracket openStore closeStore
    where
    openStore = do
        privateKey <- generatePrivate dhParams
        let publicKey = calculatePublic dhParams privateKey
        bracketOnError connectSession disconnect $ \client -> do
            reply <- call_ client $
                (serviceCall servicePath serviceInterface openSession)
                { methodCallBody = [ toVariant "dh-ietf1024-sha256-aes128-cbc-pkcs7", toVariant $ toVariant $ dumpKey publicKey ]
                , methodCallAutoStart = True
                }
            case methodReturnBody reply of
                [serverKeyVar, objectPathVar]
                    | Just v <- fromVariant objectPathVar
                    , Just skv <- fromVariant serverKeyVar
                    , Just keyDump <- fromVariant skv -> do
                    let serverKey = readKey keyDump
                    let SharedKey shared = getShared dhParams privateKey serverKey
                    let salt = BS.replicate (hashDigestSize (undefined :: SHA256)) 0
                    let prk = extract salt shared
                    let sessionKey = expand (prk :: PRK SHA256) BS.empty (128 `div` 8)
                    cipher <- throwCryptoErrorIO $ cipherInit (sessionKey :: ScrubbedBytes)
                    return CredentialStore
                        { csClient = client
                        , csSession = v
                        , csCipher = cipher
                        }
                body -> throw $ clientError $ "invalid OpenSession response" ++ show body

    closeStore = disconnect . csClient

-- |Read named credential from store. Returns 'Nothing' if credential was not found.
getCredential :: ByteArray ba => CredentialStore -> String -> IO (Maybe ba)
getCredential store@CredentialStore{..} name = do
    items <- findCredentials store name
    unlockReply <- call_ csClient $
        (serviceCall servicePath serviceInterface unlock)
            { methodCallBody = [ toVariant items ] }
    unlocked <- case methodReturnBody unlockReply of
        [ unlocked, _ ] | Just objs <- fromVariant unlocked -> return objs
        body -> throw $ clientError $ "invalid Unlock response" ++ show body
    case unlocked of
        [] -> return Nothing
        (objpath : _) -> do
            getReply <- call_ csClient $
                (serviceCall objpath itemInterface getSecret)
                    { methodCallBody = [ toVariant csSession ] }
            case methodReturnBody getReply of
                [ obj ] | Just co <- fromVariant obj ->
                    fmap Just $ decryptCredential csCipher (credParam co) (credData co)
                body -> throw $ clientError $ "invalid GetSecret response" ++ show body
  where
    credData :: CredentialObject -> BS.ByteString
    credData (_, _, v, _) = v
    credParam (_, p, _, _) = p

-- |Write named credential to store, overwriting existing one.
putCredential :: ByteArray ba => CredentialStore -> String -> ba -> IO ()
putCredential CredentialStore{..} name value = do
    (cred, iv) <- encryptCredential csCipher value
    reply <- call_ csClient $
        (serviceCall defaultCollection collectionInterface createItem)
        { methodCallBody =
            [ toVariant $ M.fromList
                [ ("org.freedesktop.Secret.Item.Label", toVariant name)
                , ("org.freedesktop.Secret.Item.Attributes",
                    toVariant $ M.singleton "credentialName" name)
                ]
            , toVariant
                ( csSession
                , iv
                , cred
                , "text/plain; charset=utf8" -- XXX who knows, really
                )
            , toVariant True
            ]
        }
    case methodReturnBody reply of
        [ path, _ ] | Just p <- fromVariant path -> when (p == noObject) $ throw (clientError "prompt required")
        body -> throw $ clientError $ "invalid CreateItem response" ++ show body

-- |Delete named credential from store.
deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential store@CredentialStore{..} name = do
    items <- findCredentials store name
    forM_ items $ \objpath ->
        call_ csClient $ serviceCall objpath itemInterface delete

findCredentials :: CredentialStore -> String -> IO [ObjectPath]
findCredentials CredentialStore{..} name = do
    searchReply <- call_ csClient $
        (serviceCall defaultCollection collectionInterface searchItems)
            { methodCallBody = [ toVariant $ M.singleton "credentialName" name ] }
    case methodReturnBody searchReply of
        [ v ] | Just items <- fromVariant v -> return items
        body -> throw $ clientError $ "invalid SearchItems response" ++ show body

decryptCredential :: (BlockCipher c, ByteArray ba) => c -> BS.ByteString -> BS.ByteString -> IO ba
decryptCredential cipher ivbytes bs = do
    iv <- case makeIV ivbytes of
        Just iv -> return iv
        Nothing -> throw $ clientError $ "invalid credential IV"
    let decrypted = cbcDecrypt cipher iv $ convert bs
    case unpad (PKCS7 $ blockSize cipher) decrypted of
        Nothing -> throw $ clientError $ "invalid decrypred credential"
        Just cred -> return cred

encryptCredential :: (BlockCipher c, ByteArray ba) => c -> ba -> IO (BS.ByteString, BS.ByteString)
encryptCredential cipher ba = do
    let padded = pad (PKCS7 $ blockSize cipher) ba
    ivbytes <- getRandomBytes (blockSize cipher)
    let Just iv = makeIV ivbytes
    let encrypted = cbcEncrypt cipher iv padded
    return (convert encrypted, ivbytes)

dumpKey :: PublicNumber -> BS.ByteString
dumpKey (PublicNumber key) = BS.reverse $ BS.unfoldr step key
  where
    step 0 = Nothing
    step i = Just (fromIntegral i, i `shiftR` 8)

readKey :: BS.ByteString -> PublicNumber
readKey = PublicNumber . BS.foldl' step 0
  where
    step i b = i `shiftL` 8 .|. fromIntegral b

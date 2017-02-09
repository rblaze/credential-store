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
import DBus
import DBus.Client
import qualified Data.ByteString as BS
import qualified Data.Map.Strict as M

import System.CredentialStore.Types

data CredentialStore = CredentialStore
    { csClient :: Client
    , csSession :: ObjectPath
    }

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

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore = bracket openStore closeStore
    where
    openStore =
        bracketOnError connectSession disconnect $ \client -> do
            reply <- call_ client $
                (serviceCall servicePath serviceInterface openSession)
                { methodCallBody = [ toVariant "plain", toVariant $ toVariant "" ]
                , methodCallAutoStart = True
                }
            case methodReturnBody reply of
                [_, objectPathVar] | Just v <- fromVariant objectPathVar ->
                    return CredentialStore
                        { csClient = client
                        , csSession = v
                        }
                body -> throw $ clientError $ "invalid OpenSession response" ++ show body

    closeStore = disconnect . csClient

getCredential :: CredentialStore -> String -> IO (Maybe Credential)
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
                [ obj ] | Just (_ :: ObjectPath, _ :: BS.ByteString, cred, _ :: String) <- fromVariant obj -> return $ Just cred
                body -> throw $ clientError $ "invalid GetSecret response" ++ show body

putCredential :: CredentialStore -> Bool -> String -> Credential -> IO ObjectPath
putCredential CredentialStore{..} replace name value = do
    reply <- call_ csClient $
        (serviceCall defaultCollection collectionInterface createItem)
        { methodCallBody =
            [ toVariant $ M.fromList
                [ ("org.freedesktop.Secret.Item.Label", toVariant $ name)
                , ("org.freedesktop.Secret.Item.Attributes",
                    toVariant $ M.singleton "credentialName" name)
                ]
            , toVariant
                ( csSession
                , BS.empty
                , value
                , "text/plain; charset=utf8" -- XXX who knows, really
                )
            , toVariant replace
            ]
        }
    case methodReturnBody reply of
        [ path, _ ] | Just p <- fromVariant path, p == noObject -> throw $ clientError "prompt required"
                    | Just p <- fromVariant path -> return p
        body -> throw $ clientError $ "invalid CreateItem response" ++ show body

deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential store@CredentialStore{..} name = do
    items <- findCredentials store name
    forM_ items $ \objpath -> do
        call_ csClient $ serviceCall objpath itemInterface delete

findCredentials :: CredentialStore -> String -> IO [ObjectPath]
findCredentials CredentialStore{..} name = do
    searchReply <- call_ csClient $
        (serviceCall defaultCollection collectionInterface searchItems)
            { methodCallBody = [ toVariant $ M.singleton "credentialName" name ] }
    case methodReturnBody searchReply of
        [ v ] | Just items <- fromVariant v -> return items
        body -> throw $ clientError $ "invalid SearchItems response" ++ show body

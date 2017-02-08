{-# Language PatternGuards, RecordWildCards #-}
module System.CredentialStore.DBusSecretService
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import Control.Exception.Safe
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

serviceOpenSession :: MemberName
serviceOpenSession = memberName_ "OpenSession"

defaultCollection :: ObjectPath
defaultCollection = objectPath_ "/org/freedesktop/secrets/aliases/default"

collectionInterface :: InterfaceName
collectionInterface = interfaceName_ "org.freedesktop.Secret.Collection"

createItem :: MemberName
createItem = memberName_ "CreateItem"

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore = bracket openStore closeStore
    where
    openStore =
        bracketOnError connectSession disconnect $ \client -> do
            reply <- call_ client $
                (methodCall servicePath serviceInterface serviceOpenSession)
                { methodCallBody = [ toVariant "plain", toVariant $ toVariant "" ]
                , methodCallAutoStart = True
                , methodCallDestination = Just destination
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
getCredential store name = undefined

putCredential :: CredentialStore -> Bool -> String -> Credential -> IO ObjectPath
putCredential CredentialStore{..} replace name value = do
    reply <- call_ csClient $
        (methodCall defaultCollection collectionInterface createItem)
        { methodCallDestination = Just destination
        , methodCallBody =
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
deleteCredential store name = undefined

module System.CredentialStore.Windows
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import System.CredentialStore.Types

data CredentialStore = CredentialStore

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore f = f CredentialStore

getCredential :: CredentialStore -> String -> IO (Maybe Credential)
getCredential _ name = undefined

putCredential :: CredentialStore -> Bool -> String -> Credential -> IO ()
putCredential _ replace name value = undefined

deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential _ name = undefined

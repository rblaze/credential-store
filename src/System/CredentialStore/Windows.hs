module System.CredentialStore.Windows
    ( getCredential
    , putCredential
    ) where

import System.CredentialStore.Types

getCredential :: String -> IO (Maybe Credential)
getCredential name = undefined

putCredential :: String -> Credential -> IO ()
putCredential name value = undefined

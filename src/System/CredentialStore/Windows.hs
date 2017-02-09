{-# Language ForeignFunctionInterface #-}
module System.CredentialStore.Windows
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import System.CredentialStore.Types
import System.CredentialStore.WinTypes

data CredentialStore = CredentialStore

targetNamePrefix :: String
targetNamePrefix = "PrivateCloud_"

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore f = f CredentialStore

getCredential :: CredentialStore -> String -> IO (Maybe Credential)
getCredential _ name = undefined

putCredential :: CredentialStore -> Bool -> String -> Credential -> IO ()
putCredential _ replace name value = undefined

deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential _ name = undefined

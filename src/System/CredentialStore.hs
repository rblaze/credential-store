{-# Language CPP #-}
module System.CredentialStore
    ( module X
    ) where

import System.CredentialStore.Types as X
#ifdef WINBUILD
import System.CredentialStore.Windows as X
#else
import System.CredentialStore.DBusSecretService as X
#endif

{-# Language CPP #-}
{-|
Cross-platform library to access system-specific credential store.

Uses Windows CredRead/CredWrite/CredDelete API on Windows,
DBus Secret Store API with gnome-keyring or kwallet as backends on Unix.
MacOS is not supported yet.

Example usage:

@
withCredentialStore $ \store -> do
    putCredential store credentialName credentialValue
    v <- getCredential store credentialName
    deleteCredential store credentialName
@
-}
module System.CredentialStore
    (
    -- * Types
      CredentialStore
    -- * Functions
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

#ifdef WINBUILD
import System.CredentialStore.Windows
#else
import System.CredentialStore.DBusSecretService
#endif

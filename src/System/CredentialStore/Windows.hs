{-# Language ForeignFunctionInterface #-}
module System.CredentialStore.Windows
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import Control.Exception.Safe
import Control.Monad
import Foreign
import System.Win32.Types
import qualified Data.ByteString as BS

import System.CredentialStore.Types
import System.CredentialStore.WinTypes

data CredentialStore = CredentialStore

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore f = f CredentialStore

getCredential :: CredentialStore -> String -> IO (Maybe Credential)
getCredential _ name =
    withTString name $ \tstr ->
        alloca $ \pptr -> do
            result <- c_CredRead tstr cRED_TYPE_GENERIC 0 pptr
            if result
                then do
                    ptr <- peek pptr
                    cred <- finally
                      (do
                        rec <- peek ptr
                        BS.packCStringLen (castPtr $ crCredentialBlob rec, fromIntegral $ crCredentialBlobSize rec)
                      ) (c_CredFree ptr)
                    return $ Just cred
                else do
                    errCode <- getLastError
                    unless (errCode == eRROR_NOT_FOUND) $ failWith "CredRead" errCode
                    return Nothing

putCredential :: CredentialStore -> Bool -> String -> Credential -> IO ()
putCredential _ replace name value = undefined

deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential _ name = undefined

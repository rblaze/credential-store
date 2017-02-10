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
import System.Win32.Time
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
putCredential _ _ name value =
    withTString name $ \tstr ->
    withTString "" $ \emptystr ->
    BS.useAsCStringLen value $ \(val, len) ->
    alloca $ \rec -> do
        poke rec CREDENTIAL
                { crFlags = 0
                , crType = cRED_TYPE_GENERIC
                , crTargetName = tstr
                , crComment = emptystr
                , crLastWritten = FILETIME 0
                , crCredentialBlobSize = fromIntegral len
                , crCredentialBlob = castPtr val
                , crPersist = cRED_PERSIST_LOCAL_MACHINE
                , crAttributeCount = 0
                , crAttributes = nullPtr
                , crTargetAlias = emptystr
                , crUserName = emptystr
                }
        failIfFalse_ "CredWrite" $ c_CredWrite rec 0

deleteCredential :: CredentialStore -> String -> IO ()
deleteCredential _ name = withTString name $ \tstr -> failIfFalse_ "CredDelete" $ c_CredDelete tstr cRED_TYPE_GENERIC 0

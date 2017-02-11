module System.CredentialStore.Windows
    ( CredentialStore
    , getCredential
    , putCredential
    , deleteCredential
    , withCredentialStore
    ) where

import Control.Exception.Safe
import Control.Monad
import Data.ByteArray
import Foreign
import System.Win32.Time
import System.Win32.Types

import System.CredentialStore.WinTypes

data CredentialStore = CredentialStore

withCredentialStore :: (CredentialStore -> IO a) -> IO a
withCredentialStore f = f CredentialStore

getCredential :: ByteArray ba => CredentialStore -> String -> IO (Maybe ba)
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
                    decryptCredential (castPtr $ crCredentialBlob rec, crCredentialBlobSize rec)
                  ) (c_CredFree ptr)
                return $ Just cred
            else do
                errCode <- getLastError
                unless (errCode == eRROR_NOT_FOUND) $ failWith "CredRead" errCode
                return Nothing

putCredential :: ByteArrayAccess ba => CredentialStore -> Bool -> String -> ba -> IO ()
putCredential _ _ name value =
    withEncryptedCredential value $ \(val, len) ->
    withTString name $ \tstr ->
    withTString "" $ \emptystr ->
    alloca $ \rec -> do
        poke rec CREDENTIAL
            { crFlags = 0
            , crType = cRED_TYPE_GENERIC
            , crTargetName = tstr
            , crComment = emptystr
            , crLastWritten = FILETIME 0
            , crCredentialBlobSize = len
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

withEncryptedCredential :: ByteArrayAccess ba => ba -> ((LPTSTR, DWORD) -> IO a) -> IO a
withEncryptedCredential value f =
    withByteArray value $ \val ->
    alloca $ \protType ->
    alloca $ \sizeptr -> do
        let len = fromIntegral $ Data.ByteArray.length value
        poke sizeptr 0
        ret <- c_CredProtect True val len nullPtr sizeptr protType
        errCode <- getLastError
        unless (not ret && errCode == eRROR_INSUFFICIENT_BUFFER) $ failWith "CredProtect(NULL)" errCode
        needed <- peek sizeptr
        allocaBytes (fromIntegral needed * 2) $ \outputPtr -> do
            failIfFalse_ "CredProtect" $ c_CredProtect True val len outputPtr sizeptr protType
            outputLen <- peek sizeptr
            f (outputPtr, outputLen * 2)

decryptCredential :: ByteArray ba => (LPTSTR, DWORD) -> IO ba
decryptCredential (val, len) =
    alloca $ \sizeptr -> do
        poke sizeptr 0
        ret <- c_CredUnprotect True val len nullPtr sizeptr
        errCode <- getLastError
        unless (not ret && errCode == eRROR_INSUFFICIENT_BUFFER) $ failWith "CredUnprotect(NULL)" errCode
        needed <- peek sizeptr
        create (fromIntegral needed) $ \outputPtr ->
            failIfFalse_ "CredUnprotect" $ c_CredUnprotect True val len outputPtr sizeptr

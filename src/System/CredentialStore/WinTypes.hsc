module System.CredentialStore.WinTypes where

#include <windows.h>
#include <wincred.h>

import Foreign.Ptr
import Foreign.Storable
import System.Win32.Time
import System.Win32.Types

data CREDENTIAL_ATTRIBUTE = CREDENTIAL_ATTRIBUTE
    { caKeyword     :: LPTSTR
    , caFlags       :: DWORD
    , caValueSize   :: DWORD
    , caValue       :: LPBYTE
    }
    deriving Show

instance Storable CREDENTIAL_ATTRIBUTE where
    sizeOf _ = #size CREDENTIAL_ATTRIBUTE
    alignment _ = #alignment CREDENTIAL_ATTRIBUTE
    poke buf st = do
        (#poke CREDENTIAL_ATTRIBUTE, Keyword)   buf (caKeyword st)
        (#poke CREDENTIAL_ATTRIBUTE, Flags)     buf (caFlags st)
        (#poke CREDENTIAL_ATTRIBUTE, ValueSize) buf (caValueSize st)
        (#poke CREDENTIAL_ATTRIBUTE, Value)     buf (caValue st)
    peek buf = do
        keyword     <- (#peek CREDENTIAL_ATTRIBUTE, Keyword) buf
        flags       <- (#peek CREDENTIAL_ATTRIBUTE, Flags) buf
        valueSize   <- (#peek CREDENTIAL_ATTRIBUTE, ValueSize) buf
        value       <- (#peek CREDENTIAL_ATTRIBUTE, Value) buf
        return $ CREDENTIAL_ATTRIBUTE keyword flags valueSize value

data CREDENTIAL = CREDENTIAL
    { crFlags               :: DWORD
    , crType                :: DWORD
    , crTargetName          :: LPTSTR
    , crComment             :: LPTSTR
    , crLastWritten         :: FILETIME
    , crCredentialBlobSize  :: DWORD
    , crCredentialBlob      :: LPBYTE
    , crPersist             :: DWORD
    , crAttributeCount      :: DWORD
    , crAttributes          :: Ptr CREDENTIAL_ATTRIBUTE
    , crTargetAlias         :: LPTSTR
    , crUserName            :: LPTSTR
    }
    deriving Show

instance Storable CREDENTIAL where
    sizeOf _ = #size CREDENTIAL
    alignment _ = #alignment CREDENTIAL
    poke buf st = do
        (#poke CREDENTIAL, Flags)              buf (crFlags st)
        (#poke CREDENTIAL, Type)               buf (crType st)
        (#poke CREDENTIAL, TargetName)         buf (crTargetName st)
        (#poke CREDENTIAL, Comment)            buf (crComment st)
        (#poke CREDENTIAL, LastWritten)        buf (crLastWritten st)
        (#poke CREDENTIAL, CredentialBlobSize) buf (crCredentialBlobSize st)
        (#poke CREDENTIAL, CredentialBlob)     buf (crCredentialBlob st)
        (#poke CREDENTIAL, Persist)            buf (crPersist st)
        (#poke CREDENTIAL, AttributeCount)     buf (crAttributeCount st)
        (#poke CREDENTIAL, Attributes)         buf (crAttributes st)
        (#poke CREDENTIAL, TargetAlias)        buf (crTargetAlias st)
        (#poke CREDENTIAL, UserName)           buf (crUserName st)
    peek buf = do
        flags              <- (#peek CREDENTIAL, Flags) buf
        type'              <- (#peek CREDENTIAL, Type) buf
        targetName         <- (#peek CREDENTIAL, TargetName) buf
        comment            <- (#peek CREDENTIAL, Comment) buf
        lastWritten        <- (#peek CREDENTIAL, LastWritten) buf
        credentialBlobSize <- (#peek CREDENTIAL, CredentialBlobSize) buf
        credentialBlob     <- (#peek CREDENTIAL, CredentialBlob) buf
        persist            <- (#peek CREDENTIAL, Persist) buf
        attributeCount     <- (#peek CREDENTIAL, AttributeCount) buf
        attributes         <- (#peek CREDENTIAL, Attributes) buf
        targetAlias        <- (#peek CREDENTIAL, TargetAlias) buf
        userName           <- (#peek CREDENTIAL, UserName) buf
        return $ CREDENTIAL flags type' targetName comment lastWritten credentialBlobSize credentialBlob persist attributeCount attributes targetAlias userName

cRED_TYPE_GENERIC :: DWORD
cRED_TYPE_GENERIC = 1

foreign import ccall unsafe "CredReadW" c_CredRead :: LPCTSTR -> DWORD -> DWORD -> Ptr (Ptr CREDENTIAL) -> IO BOOL

foreign import ccall unsafe "CredFree" c_CredFree :: Ptr CREDENTIAL -> IO ()

eRROR_NOT_FOUND :: ErrCode
eRROR_NOT_FOUND = #const ERROR_NOT_FOUND

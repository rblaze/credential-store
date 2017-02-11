module Main where

import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main =
    withCredentialStore $ \store -> do
        putCredential store True "foo" (BS8.pack "burr")
        v <- getCredential store "foo"
        print (v :: Maybe BS8.ByteString)
        deleteCredential store "foo"
        v' <- getCredential store "foo"
        print (v' :: Maybe BS8.ByteString)

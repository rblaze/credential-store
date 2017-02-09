module Main where

import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main = do
    withCredentialStore $ \store -> do
        objid <- putCredential store True "foo" (BS8.pack "burr")
        print objid
        v <- getCredential store "foo"
        print v

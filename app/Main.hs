module Main where

import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main = do
    withCredentialStore $ \store -> do
--        putCredential store True "foo" (BS8.pack "burr")
        v <- getCredential store "git:https://github.com"
        print v
        v <- getCredential store "it:https://github.com"
        print v
--        deleteCredential store "foo"
--        v' <- getCredential store "foo"
--        print v'

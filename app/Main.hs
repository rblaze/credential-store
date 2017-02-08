module Main where

import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main = do
    putCredential "testcred" (BS8.pack "credvalue") 
    cred <- getCredential "testcred"
    print cred

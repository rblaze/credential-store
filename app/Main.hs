module Main where

import Control.Monad
import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main = do
    withCredentialStore $ \store -> do
        void $ putCredential store True "foo" (BS8.pack "buzz")

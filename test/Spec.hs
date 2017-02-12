import Test.Tasty
import Test.Tasty.HUnit
import qualified Data.ByteString.Char8 as BS8

import System.CredentialStore

main :: IO ()
main = defaultMain tests

tests :: TestTree
tests = testGroup "Credential store"
    [ testCase "Save-load-delete credential" testCred
    ]

testCred :: Assertion
testCred = withCredentialStore $ \store -> do
    putCredential store credentialName credentialValue
    v <- getCredential store credentialName
    assertEqual "value don't match" (Just credentialValue) v
    deleteCredential store credentialName
    v' <- getCredential store credentialName
    assertEqual "value not deleted" Nothing (v' :: Maybe BS8.ByteString)
    where
    credentialName = "credential-store-test"
    credentialValue = BS8.pack "foobar"

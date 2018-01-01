# credential-store
Windows and Linux credentials storage

Cross-platform library to access system-specific credential store.

Uses Windows CredRead/CredWrite/CredDelete API on Windows, DBus SecretStore API with gnome-keyring or kwallet as backends on Unix. MacOS is not supported yet.

Example usage:

    withCredentialStore $ \store -> do
        putCredential store credentialName credentialValue
        v <- getCredential store credentialName
        deleteCredential store credentialName

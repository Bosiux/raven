package crypto_test

import (
    "path/filepath"
    "testing"

    "raven-server/pkg/crypto"
)

func TestLoadOrCreateHostKey(t *testing.T) {

    tempDir := t.TempDir()
    keyPath := filepath.Join(tempDir, "test_host.key")

    pub1, _, err := crypto.LoadOrCreateHostKey(keyPath)
    if err != nil {
        t.Fatalf("error generating key: %v", err)
    }

    pub2, priv2, err := crypto.LoadOrCreateHostKey(keyPath)
    if err != nil {
        t.Fatalf("error loading existing key: %v", err)
    }

    if !crypto.VerifyKey(pub2, priv2) {
        t.Error("Invalid key pair")
    }

    if string(pub1) != string(pub2) {
        t.Error("Public keys mismatch")
    }
}

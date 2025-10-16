package crypto

import (
    "crypto/ed25519"
    "crypto/rand"
    "encoding/pem"
    "errors"
    "fmt"
    "os"
    "path/filepath"
)

// generate ED25519 key pair
func GenerateKey() (ed25519.PublicKey, ed25519.PrivateKey, error) {
    return ed25519.GenerateKey(rand.Reader)
}

// save Ed25519 key in PEM format
func SavePrivateKey(privateKey ed25519.PrivateKey, path string) error {
    if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
        return fmt.Errorf("error creating directory: %w", err)
    }

    pemBlock := &pem.Block{
        Type:  "ED25519 PRIVATE KEY",
        Bytes: privateKey,
    }

    return os.WriteFile(path, pem.EncodeToMemory(pemBlock), 0600)
}

// load private key from file
func LoadPrivateKey(path string) (ed25519.PrivateKey, error) {
    data, err := os.ReadFile(path)
    if err != nil {
        return nil, fmt.Errorf("error reading private key: %w", err)
    }

    block, _ := pem.Decode(data)
    if block == nil || block.Type != "ED25519 PRIVATE KEY" {
        return nil, errors.New("invalid PEM format or type")
    }

    return ed25519.PrivateKey(block.Bytes), nil
}

// load existing key or create it new
func LoadOrCreateHostKey(path string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
    privateKey, err := LoadPrivateKey(path)
    if err == nil {
        return privateKey.Public().(ed25519.PublicKey), privateKey, nil
    }

    // generate it
    pub, priv, err := GenerateKey()
    if err != nil {
        return nil, nil, fmt.Errorf("error generating host key: %w", err)
    }

    if err := SavePrivateKey(priv, path); err != nil {
        return nil, nil, fmt.Errorf("error saving host key: %w", err)
    }

    return pub, priv, nil
}

// check key pair validity
func VerifyKey(publicKey ed25519.PublicKey, privateKey ed25519.PrivateKey) bool {
    derivedPub := privateKey.Public().(ed25519.PublicKey)
    return string(derivedPub) == string(publicKey)
}

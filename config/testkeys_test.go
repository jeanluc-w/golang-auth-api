package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"github.com/youmark/pkcs8"
)

// writeEd25519KeyPair generates a fresh Ed25519 keypair and writes it as a
// PEM-encoded PKCS8 private key + PKIX public key, matching the format
// loadPrivateKey/loadPublicKey expect. Returns the file paths.
func writeEd25519KeyPair(t *testing.T, dir string) (privFile, pubFile string, pub ed25519.PublicKey, priv ed25519.PrivateKey) {
	t.Helper()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	privFile = filepath.Join(dir, "private.pem")
	writePEM(t, privFile, "PRIVATE KEY", privDER)

	pubDER, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubFile = filepath.Join(dir, "public.pem")
	writePEM(t, pubFile, "PUBLIC KEY", pubDER)

	return privFile, pubFile, pub, priv
}

// writeEncryptedPrivateKey PEM-encodes priv as an "ENCRYPTED PRIVATE KEY"
// block protected by passphrase, matching what loadPrivateKey's
// ENCRYPTED PRIVATE KEY branch expects.
func writeEncryptedPrivateKey(t *testing.T, dir string, priv ed25519.PrivateKey, passphrase string) string {
	t.Helper()

	der, err := pkcs8.MarshalPrivateKey(priv, []byte(passphrase), nil)
	if err != nil {
		t.Fatalf("pkcs8.MarshalPrivateKey: %v", err)
	}
	file := filepath.Join(dir, "private_encrypted.pem")
	writePEM(t, file, "ENCRYPTED PRIVATE KEY", der)
	return file
}

// writeWrongTypePrivateKeyFile writes a syntactically valid "PRIVATE KEY"
// PEM block that decodes to an RSA key instead of ed25519 — exercises
// loadPrivateKey's type-assertion failure branch, which is a real logic
// check rather than just "file missing/corrupt".
func writeWrongTypePrivateKeyFile(t *testing.T, dir string) string {
	t.Helper()

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	file := filepath.Join(dir, "private_wrong_type.pem")
	writePEM(t, file, "PRIVATE KEY", der)
	return file
}

// writeCorruptPEMFile writes a file that is not valid PEM at all.
func writeCorruptPEMFile(t *testing.T, dir string) string {
	t.Helper()
	file := filepath.Join(dir, "corrupt.pem")
	if err := os.WriteFile(file, []byte("this is not a PEM file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return file
}

func writePEM(t *testing.T, file, blockType string, der []byte) {
	t.Helper()
	f, err := os.Create(file)
	if err != nil {
		t.Fatalf("os.Create(%s): %v", file, err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		t.Fatalf("pem.Encode: %v", err)
	}
}

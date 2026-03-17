package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/argon2"
	"golang.org/x/term"
)

type encryptedMasterKey struct {
	Version    int    `json:"v"`
	Algorithm  string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type masterKeyMeta struct {
	Version     int    `json:"v"`
	KDF         string `json:"kdf"`
	Salt        string `json:"salt"`
	Memory      uint32 `json:"memory"`
	Iterations  uint32 `json:"iterations"`
	Parallelism uint8  `json:"parallelism"`
	KeyLength   uint32 `json:"key_length"`
}

func main() {
	password, err := promptPasswordTwice()
	if err != nil {
		panic(err)
	}

	salt, err := randomBytes(16)
	if err != nil {
		panic(err)
	}

	const (
		memory      uint32 = 19 * 1024 // 19 MiB
		iterations  uint32 = 2
		parallelism uint8  = 1
		keyLength   uint32 = 32
	)

	derivedKey := argon2.IDKey(
		[]byte(password),
		salt,
		iterations,
		memory,
		parallelism,
		keyLength,
	)

	masterKey, err := randomBytes(32)
	if err != nil {
		panic(err)
	}

	block, err := aes.NewCipher(derivedKey)
	if err != nil {
		panic(err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		panic(err)
	}

	nonce, err := randomBytes(uint32(aead.NonceSize()))
	if err != nil {
		panic(err)
	}

	ciphertext := aead.Seal(nil, nonce, masterKey, nil)

	meta := masterKeyMeta{
		Version:     1,
		KDF:         "argon2id",
		Salt:        base64.StdEncoding.EncodeToString(salt),
		Memory:      memory,
		Iterations:  iterations,
		Parallelism: parallelism,
		KeyLength:   keyLength,
	}

	enc := encryptedMasterKey{
		Version:    1,
		Algorithm:  "aes-256-gcm",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	if err := os.MkdirAll("secrets", 0o700); err != nil {
		panic(err)
	}

	metaPath := filepath.Join("secrets", "db.key.meta")
	encPath := filepath.Join("secrets", "db.key.enc")

	if err := writeJSON(metaPath, meta, 0o600); err != nil {
		panic(err)
	}
	if err := writeJSON(encPath, enc, 0o600); err != nil {
		panic(err)
	}

	fmt.Println("Clave maestra protegida generada correctamente:")
	fmt.Println(" -", metaPath)
	fmt.Println(" -", encPath)
	fmt.Println("Puedes borrar cualquier antiguo secrets/db.key en claro si existiera.")
}

func promptPasswordTwice() (string, error) {
	fmt.Print("Introduce la contraseña maestra del servidor: ")
	pw1, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}

	fmt.Print("Repite la contraseña maestra: ")
	pw2, err := term.ReadPassword(int(syscall.Stdin))
	fmt.Println()
	if err != nil {
		return "", err
	}

	if string(pw1) != string(pw2) {
		return "", errors.New("las contraseñas no coinciden")
	}

	if strings.TrimSpace(string(pw1)) == "" {
		return "", errors.New("la contraseña no puede estar vacía")
	}

	if len([]byte(string(pw1))) < 8 {
		return "", errors.New("la contraseña debe tener al menos 8 caracteres")
	}

	return string(pw1), nil
}

func randomBytes(n uint32) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func writeJSON(path string, v any, perm os.FileMode) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, perm)
}

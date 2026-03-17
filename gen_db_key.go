package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
)

func main() {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		panic(err)
	}

	if err := os.MkdirAll("secrets", 0o700); err != nil {
		panic(err)
	}

	path := filepath.Join("secrets", "db.key")
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(key)), 0o600); err != nil {
		panic(err)
	}

	fmt.Println("Clave generada en:", path)
}

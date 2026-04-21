package store

import (
	"bytes"
	"compress/zlib"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"go.etcd.io/bbolt"
)

/*
	Implementación de la interfaz Store mediante BoltDB (versión bbolt)
*/

// BboltStore contiene la instancia de la base de datos bbolt.
type BboltStore struct {
	db        *bbolt.DB
	masterKey []byte // RGS
}

type encryptedValue struct {
	Version    int    `json:"v"`
	Algorithm  string `json:"alg"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}
 // RGS
// NewBboltStore abre la base de datos bbolt en la ruta especificada.
func NewBboltStore(path string, masterKey []byte) (*BboltStore, error) {
	if len(masterKey) != 32 {
		return nil, errors.New("la clave maestra debe tener 32 bytes")
	}

	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, err
	}

	return &BboltStore{
		db:        db,
		masterKey: append([]byte(nil), masterKey...),
	}, nil
}

 func (s *BboltStore) encryptValue(plaintext []byte) ([]byte, error) {
	compressed, err := zlibCompress(plaintext)
	if err != nil {
		return nil, fmt.Errorf("comprimiendo valor: %w", err)
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("creando AES: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creando GCM: %w", err)
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generando nonce: %w", err)
	}

	ciphertext := aead.Seal(nil, nonce, compressed, nil)

	record := encryptedValue{
		Version:    1,
		Algorithm:  "aes-256-gcm+zlib",
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}

	out, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("serializando valor cifrado: %w", err)
	}

	return out, nil
}

func (s *BboltStore) decryptValue(blob []byte) ([]byte, error) {
	var record encryptedValue
	if err := json.Unmarshal(blob, &record); err != nil {
		return nil, fmt.Errorf("parseando valor cifrado: %w", err)
	}

	if record.Version != 1 || record.Algorithm != "aes-256-gcm+zlib" {
		return nil, errors.New("formato cifrado no soportado")
	}

	nonce, err := base64.StdEncoding.DecodeString(record.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decodificando nonce: %w", err)
	}

	ciphertext, err := base64.StdEncoding.DecodeString(record.Ciphertext)
	if err != nil {
		return nil, fmt.Errorf("decodificando ciphertext: %w", err)
	}

	block, err := aes.NewCipher(s.masterKey)
	if err != nil {
		return nil, fmt.Errorf("creando AES: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("creando GCM: %w", err)
	}

	compressed, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("descifrando valor: %w", err)
	}

	plaintext, err := zlibDecompress(compressed)
	if err != nil {
		return nil, fmt.Errorf("descomprimiendo valor: %w", err)
	}

	return plaintext, nil
}

func zlibCompress(data []byte) ([]byte, error) {
	var buf bytes.Buffer

	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(data); err != nil {
		_ = zw.Close()
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func zlibDecompress(data []byte) ([]byte, error) {
	zr, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()

	return io.ReadAll(zr)
}
 // RGS



// Put almacena o actualiza (key, value) dentro de un bucket = namespace.
// No se soportan sub-buckets.
func (s *BboltStore) Put(namespace string, key, value []byte) error {
	protectedValue, err := s.encryptValue(value) // RGS
	if err != nil {
		return fmt.Errorf("protegiendo valor antes de guardar: %w", err)
	}

	return s.db.Update(func(tx *bbolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists([]byte(namespace))
		if err != nil {
			return fmt.Errorf("creando bucket %s: %w", namespace, err)
		}
		return b.Put(key, protectedValue)
	})
}

// Get recupera el valor de (key) en el bucket = namespace.
func (s *BboltStore) Get(namespace string, key []byte) ([]byte, error) {
	var raw []byte

	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return ErrNamespaceNotFound
		}

		v := b.Get(key)
		if v == nil {
			return ErrKeyNotFound
		}

		raw = make([]byte, len(v))
		copy(raw, v)
		return nil
	})
	if err != nil {
		return nil, err
	}

	plaintext, err := s.decryptValue(raw) // RGS
	if err != nil {
		return nil, fmt.Errorf("descifrando valor de %s/%s: %w", namespace, string(key), err)
	}

	return plaintext, nil
}

// Delete elimina la clave 'key' del bucket = namespace.
func (s *BboltStore) Delete(namespace string, key []byte) error {
	return s.db.Update(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("%w: %s", ErrNamespaceNotFound, namespace)
		}
		return b.Delete(key)
	})
}

// ListKeys devuelve todas las claves del bucket = namespace.
func (s *BboltStore) ListKeys(namespace string) ([][]byte, error) {
	var keys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("%w: %s", ErrNamespaceNotFound, namespace)
		}
		c := b.Cursor()
		for k, _ := c.First(); k != nil; k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			keys = append(keys, kCopy)
		}
		return nil
	})
	return keys, err
}

// KeysByPrefix devuelve las claves que inicien con 'prefix' en el bucket = namespace.
func (s *BboltStore) KeysByPrefix(namespace string, prefix []byte) ([][]byte, error) {
	var matchedKeys [][]byte
	err := s.db.View(func(tx *bbolt.Tx) error {
		b := tx.Bucket([]byte(namespace))
		if b == nil {
			return fmt.Errorf("%w: %s", ErrNamespaceNotFound, namespace)
		}
		c := b.Cursor()
		for k, _ := c.Seek(prefix); k != nil && bytes.HasPrefix(k, prefix); k, _ = c.Next() {
			kCopy := make([]byte, len(k))
			copy(kCopy, k)
			matchedKeys = append(matchedKeys, kCopy)
		}
		return nil
	})
	return matchedKeys, err
}

// Close cierra la base de datos bbolt.
func (s *BboltStore) Close() error {
	return s.db.Close()
}

// Dump imprime todo el contenido de la base de datos bbolt para propósitos de depuración.
func (s *BboltStore) Dump() error {
	// Nota: para depuración, aquí preferimos imprimir y no devolver un tipo de
	// salida estructurado.
	err := s.db.View(func(tx *bbolt.Tx) error {
		return tx.ForEach(func(bucketName []byte, b *bbolt.Bucket) error {
			fmt.Printf("Bucket: %s\n", string(bucketName))
			return b.ForEach(func(k, v []byte) error {
				fmt.Printf("  Key: %s, Value: %s\n", string(k), string(v))
				return nil
			})
		})
	})
	if err != nil {
		// Si alguien cierra la DB por debajo (o hay E/S), el error se propaga.
		// Mantenemos el contexto.
		return fmt.Errorf("error al hacer el volcado de depuración: %w", err)
	}
	return nil
}
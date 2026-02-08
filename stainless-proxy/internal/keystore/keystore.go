package keystore

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/go-jose/go-jose/v4"
)

type KeyEntry struct {
	KID        string
	PrivateKey *ecdsa.PrivateKey
	PublicKey  *ecdsa.PublicKey
	CreatedAt  time.Time
}

type KeyStore struct {
	keys []KeyEntry
}

func New(keyDir string, generateIfEmpty bool) (*KeyStore, error) {
	ks := &KeyStore{}

	if keyDir != "" {
		if err := ks.loadFromDir(keyDir); err != nil {
			return nil, fmt.Errorf("loading keys: %w", err)
		}
	}

	if len(ks.keys) == 0 {
		if !generateIfEmpty {
			return nil, fmt.Errorf("no keys found and generation disabled")
		}
		entry, err := generateKey()
		if err != nil {
			return nil, fmt.Errorf("generating key: %w", err)
		}
		ks.keys = append(ks.keys, entry)

		if keyDir != "" {
			if err := os.MkdirAll(keyDir, 0700); err != nil {
				return nil, fmt.Errorf("creating key directory: %w", err)
			}
			path := filepath.Join(keyDir, fmt.Sprintf("key-%s.pem", time.Now().Format("2006-01-02")))
			if err := writeKeyFile(path, entry.PrivateKey); err != nil {
				return nil, fmt.Errorf("writing key: %w", err)
			}
		}
	}

	sort.Slice(ks.keys, func(i, j int) bool {
		return ks.keys[i].CreatedAt.After(ks.keys[j].CreatedAt)
	})

	return ks, nil
}

func (ks *KeyStore) JWKS() jose.JSONWebKeySet {
	var keys []jose.JSONWebKey
	for _, entry := range ks.keys {
		keys = append(keys, jose.JSONWebKey{
			Key:       entry.PublicKey,
			KeyID:     entry.KID,
			Algorithm: string(jose.ECDH_ES_A256KW),
			Use:       "enc",
		})
	}
	return jose.JSONWebKeySet{Keys: keys}
}

func (ks *KeyStore) PrimaryKey() KeyEntry {
	return ks.keys[0]
}

func (ks *KeyStore) Keys() []KeyEntry {
	return ks.keys
}

func (ks *KeyStore) loadFromDir(dir string) error {
	matches, err := filepath.Glob(filepath.Join(dir, "*.pem"))
	if err != nil {
		return fmt.Errorf("globbing key files: %w", err)
	}

	for _, path := range matches {
		entry, err := loadKeyFile(path)
		if err != nil {
			return fmt.Errorf("loading %s: %w", path, err)
		}
		ks.keys = append(ks.keys, entry)
	}
	return nil
}

func generateKey() (KeyEntry, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("generating ECDSA key: %w", err)
	}

	kid, err := thumbprint(priv)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("computing thumbprint: %w", err)
	}

	return KeyEntry{
		KID:        kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		CreatedAt:  time.Now(),
	}, nil
}

func thumbprint(key *ecdsa.PrivateKey) (string, error) {
	jwk := jose.JSONWebKey{Key: &key.PublicKey}
	kid, err := jwk.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(kid), nil
}

func loadKeyFile(path string) (KeyEntry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KeyEntry{}, err
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return KeyEntry{}, fmt.Errorf("no PEM block found")
	}

	priv, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("parsing EC private key: %w", err)
	}

	kid, err := thumbprint(priv)
	if err != nil {
		return KeyEntry{}, fmt.Errorf("computing thumbprint: %w", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		return KeyEntry{}, err
	}

	return KeyEntry{
		KID:        kid,
		PrivateKey: priv,
		PublicKey:  &priv.PublicKey,
		CreatedAt:  info.ModTime(),
	}, nil
}

func writeKeyFile(path string, key *ecdsa.PrivateKey) error {
	der, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshaling key: %w", err)
	}

	block := &pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: der,
	}

	return os.WriteFile(path, pem.EncodeToMemory(block), 0600)
}


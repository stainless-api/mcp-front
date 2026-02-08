package jwe

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/stainless-api/stainless-proxy/internal/secretutil"
)

type Credential struct {
	Header string `json:"header"`
	Value  string `json:"value"`
}

type Payload struct {
	Exp          int64        `json:"exp"`
	AllowedHosts []string     `json:"allowed_hosts"`
	Credentials  []Credential `json:"credentials"`
}

type Encryptor struct {
	publicKey *ecdsa.PublicKey
	kid       string
}

func NewEncryptor(publicKey *ecdsa.PublicKey, kid string) *Encryptor {
	return &Encryptor{publicKey: publicKey, kid: kid}
}

func (e *Encryptor) Encrypt(payload Payload) (string, error) {
	plaintext, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshaling payload: %w", err)
	}

	recipient := jose.Recipient{
		Algorithm: jose.ECDH_ES_A256KW,
		Key:       e.publicKey,
		KeyID:     e.kid,
	}

	enc, err := jose.NewEncrypter(
		jose.A256GCM,
		recipient,
		(&jose.EncrypterOptions{}).WithContentType("JWT"),
	)
	if err != nil {
		return "", fmt.Errorf("creating encrypter: %w", err)
	}

	obj, err := enc.Encrypt(plaintext)
	if err != nil {
		return "", fmt.Errorf("encrypting: %w", err)
	}

	return obj.CompactSerialize()
}

type Decryptor interface {
	Decrypt(token string) (*Payload, error)
}

type KeyEntry struct {
	KID        string
	PrivateKey *ecdsa.PrivateKey
}

type MultiKeyDecryptor struct {
	keys map[string]*ecdsa.PrivateKey
}

func NewMultiKeyDecryptor(keys []KeyEntry) *MultiKeyDecryptor {
	m := make(map[string]*ecdsa.PrivateKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.PrivateKey
	}
	return &MultiKeyDecryptor{keys: m}
}

// decryptAndValidate decrypts the JWE and validates the payload.
// This function is isolated so it can be wrapped in runtime/secret.Do()
// once Go 1.26 is stable — all plaintext credential handling happens here.
func (d *MultiKeyDecryptor) decryptAndValidate(token string) (*Payload, error) {
	obj, err := jose.ParseEncrypted(token,
		[]jose.KeyAlgorithm{jose.ECDH_ES_A256KW},
		[]jose.ContentEncryption{jose.A256GCM},
	)
	if err != nil {
		return nil, fmt.Errorf("parsing JWE: %w", err)
	}

	kid := obj.Header.KeyID
	key, ok := d.keys[kid]
	if !ok {
		return nil, fmt.Errorf("unknown key ID: %s", kid)
	}

	plaintext, err := obj.Decrypt(key)
	if err != nil {
		return nil, fmt.Errorf("decrypting: %w", err)
	}

	var payload Payload
	if err := json.Unmarshal(plaintext, &payload); err != nil {
		zeroBytes(plaintext)
		return nil, fmt.Errorf("unmarshaling payload: %w", err)
	}
	zeroBytes(plaintext)

	if payload.Exp > 0 && time.Now().Unix() > payload.Exp {
		return nil, fmt.Errorf("token expired")
	}

	if len(payload.AllowedHosts) == 0 {
		return nil, fmt.Errorf("allowed_hosts is required")
	}

	if len(payload.Credentials) == 0 {
		return nil, fmt.Errorf("credentials is required")
	}

	return &payload, nil
}

func (d *MultiKeyDecryptor) Decrypt(token string) (*Payload, error) {
	var (
		payload *Payload
		decErr  error
	)
	// secret.Do zeros stack frames, registers, and (with GOEXPERIMENT=runtimesecret)
	// marks heap allocations for zeroing on GC. This covers:
	//   - plaintext []byte from go-jose's obj.Decrypt()
	//   - go-jose's internal AES-GCM / ECDH intermediate buffers
	//   - json.Unmarshal's working memory
	// The returned *Payload escapes the closure (still reachable), but its
	// string fields will be zeroed by GC once the Payload becomes unreachable.
	secretutil.Do(func() {
		payload, decErr = d.decryptAndValidate(token)
	})
	return payload, decErr
}

// zeroBytes overwrites b with zeros. Called immediately after unmarshal
// so the raw JSON containing credential values doesn't linger on the heap.
//
//go:noinline
func zeroBytes(b []byte) {
	clear(b)
}

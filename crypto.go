package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

const (
	envelopeKey   = "\x00skate/envelope"
	valueMagic    = "skate:v1:"
	kdfIterations = 600000
	dataKeySize   = 32
	nonceSize     = 12
)

var (
	errEncryptedDBNotInitialized = errors.New("encrypted database is not initialized")
	errEncryptedValueFormat      = errors.New("encrypted value has an invalid format")
)

type keyEnvelope struct {
	Version      int    `json:"version"`
	KDF          string `json:"kdf"`
	Iterations   int    `json:"iterations"`
	Salt         string `json:"salt"`
	Nonce        string `json:"nonce"`
	EncryptedKey string `json:"encrypted_key"`
}

func newKeyEnvelope(passphrase string) (keyEnvelope, []byte, error) {
	dataKey := make([]byte, dataKeySize)
	if _, err := rand.Read(dataKey); err != nil {
		return keyEnvelope{}, nil, fmt.Errorf("generate data key: %w", err)
	}
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return keyEnvelope{}, nil, fmt.Errorf("generate salt: %w", err)
	}
	passKey, err := derivePassphraseKey(passphrase, salt, kdfIterations)
	if err != nil {
		return keyEnvelope{}, nil, err
	}
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return keyEnvelope{}, nil, fmt.Errorf("generate nonce: %w", err)
	}
	ciphertext, err := seal(passKey, nonce, dataKey, nil)
	if err != nil {
		return keyEnvelope{}, nil, err
	}
	return keyEnvelope{
		Version:      1,
		KDF:          "pbkdf2-sha256",
		Iterations:   kdfIterations,
		Salt:         base64.StdEncoding.EncodeToString(salt),
		Nonce:        base64.StdEncoding.EncodeToString(nonce),
		EncryptedKey: base64.StdEncoding.EncodeToString(ciphertext),
	}, dataKey, nil
}

func marshalEnvelope(envelope keyEnvelope) ([]byte, error) {
	bts, err := json.Marshal(envelope)
	if err != nil {
		return nil, fmt.Errorf("marshal key envelope: %w", err)
	}
	return bts, nil
}

func unmarshalEnvelope(bts []byte) (keyEnvelope, error) {
	var envelope keyEnvelope
	if err := json.Unmarshal(bts, &envelope); err != nil {
		return keyEnvelope{}, fmt.Errorf("parse key envelope: %w", err)
	}
	if envelope.Version != 1 || envelope.KDF != "pbkdf2-sha256" {
		return keyEnvelope{}, fmt.Errorf("unsupported key envelope")
	}
	return envelope, nil
}

func unlockDataKey(envelope keyEnvelope, passphrase string) ([]byte, error) {
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil {
		return nil, fmt.Errorf("decode envelope salt: %w", err)
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, fmt.Errorf("decode envelope nonce: %w", err)
	}
	if len(nonce) != nonceSize {
		return nil, fmt.Errorf("decode envelope nonce: invalid length")
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("decode encrypted data key: %w", err)
	}
	passKey, err := derivePassphraseKey(passphrase, salt, envelope.Iterations)
	if err != nil {
		return nil, err
	}
	dataKey, err := open(passKey, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("unlock database: %w", err)
	}
	if len(dataKey) != dataKeySize {
		return nil, fmt.Errorf("unlock database: invalid data key size")
	}
	return dataKey, nil
}

func envelopeFingerprint(envelope keyEnvelope) string {
	bts, err := json.Marshal(envelope)
	if err != nil {
		sum := sha256.Sum256([]byte(envelope.EncryptedKey))
		return base64.StdEncoding.EncodeToString(sum[:])
	}
	sum := sha256.Sum256(bts)
	return base64.StdEncoding.EncodeToString(sum[:])
}

func encryptValue(dataKey, itemKey, value []byte) ([]byte, error) {
	nonce := make([]byte, nonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("generate value nonce: %w", err)
	}
	ciphertext, err := seal(dataKey, nonce, value, itemKey)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(valueMagic)+len(nonce)+len(ciphertext))
	out = append(out, valueMagic...)
	out = append(out, nonce...)
	out = append(out, ciphertext...)
	return out, nil
}

func decryptValue(dataKey, itemKey, value []byte) ([]byte, error) {
	if !bytes.HasPrefix(value, []byte(valueMagic)) {
		return nil, errEncryptedValueFormat
	}
	payload := value[len(valueMagic):]
	if len(payload) < nonceSize {
		return nil, errEncryptedValueFormat
	}
	plaintext, err := open(dataKey, payload[:nonceSize], payload[nonceSize:], itemKey)
	if err != nil {
		return nil, fmt.Errorf("decrypt value: %w", err)
	}
	return plaintext, nil
}

func derivePassphraseKey(passphrase string, salt []byte, iterations int) ([]byte, error) {
	key, err := pbkdf2.Key(sha256.New, passphrase, salt, iterations, dataKeySize)
	if err != nil {
		return nil, fmt.Errorf("derive passphrase key: %w", err)
	}
	return key, nil
}

func seal(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	return aead.Seal(nil, nonce, plaintext, additionalData), nil
}

func open(key, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("create cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("create gcm: %w", err)
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, additionalData)
	if err != nil {
		return nil, fmt.Errorf("open cipher: %w", err)
	}
	return plaintext, nil
}

func readSecret(r io.Reader) (string, error) {
	bts, err := io.ReadAll(r)
	if err != nil {
		return "", fmt.Errorf("read secret: %w", err)
	}
	return string(bytes.TrimRight(bts, "\r\n")), nil
}

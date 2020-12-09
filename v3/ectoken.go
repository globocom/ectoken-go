package v3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
)

const (
	ivLength = 12
)

// Encrypt given a key and opts (key/value formatted string)
// encrypts the message, generating a valid token to be used in
// EdgeCast products.
func Encrypt(key string, opts string) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(key))

	cipherBlock, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	iv := RandomIV{size: 12}
	randomIV, err := iv.Generate()
	if err != nil {
		return "", err
	}

	token := gcm.Seal(randomIV, randomIV, []byte(opts), nil)

	return base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString(token), nil
}

// Decrypt decrypt a token to reveal the options used to generate it
func Decrypt(key string, token string) (string, error) {
	hash := sha256.New()
	hash.Write([]byte(key))

	cipherBlock, err := aes.NewCipher(hash.Sum(nil))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(cipherBlock)
	if err != nil {
		return "", err
	}

	opts, err := base64.URLEncoding.WithPadding(base64.NoPadding).DecodeString(token)
	if err != nil {
		return "", err
	}

	iv := opts[0:ivLength]
	cipherText := opts[ivLength:]

	params, err := gcm.Open(nil, iv, cipherText, nil)
	if err != nil {
		return "", err
	}

	return string(params), nil
}

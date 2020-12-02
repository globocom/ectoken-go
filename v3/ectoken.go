package v3

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
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

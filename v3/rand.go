package v3

import "crypto/rand"

// RandomIV random IV generator.
type RandomIV struct {
	size int
}

// Generate creates a random IV
func (iv *RandomIV) Generate() ([]byte, error) {
	buf := make([]byte, iv.size)
	if _, err := rand.Read(buf); err != nil {
		return nil, err
	}

	return buf, nil
}

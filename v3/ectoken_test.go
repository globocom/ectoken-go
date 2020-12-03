package v3_test

import (
	"testing"

	v3 "github.com/globocom/ectoken-go/v3"
)

const (
	opts = "ec_expire=123&ec_url_allow=/foo/bar"
)

func TestDecrypt(t *testing.T) {
	token, err := v3.Encrypt("bazfoo", opts)
	if err != nil {
		t.Error(err)
	}

	decoded, err := v3.Decrypt("bazfoo", token)
	if err != nil {
		t.Error(err)
	}

	if decoded != opts {
		t.Errorf("expected token to be %s but got %s", opts, decoded)
	}
}

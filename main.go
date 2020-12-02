package main

import (
	"log"
	"os"

	v3 "github.com/globocom/ectoken-go/v3"
)

func main() {
	key := "key"
	opts := "opts"
	token, err := v3.Encrypt(key, opts)
	if err != nil {
		os.Exit(1)
	}
	log.Printf("token: %s", token)
}

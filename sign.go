package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
)

//PrivateKey is ed25519.PrivateKey.
type PrivateKey ed25519.PrivateKey

//GetPrivateKey reads the private key from input file and
//returns the initialized PrivateKey.
func GetPrivateKey(privateKey string) (PrivateKey, error) {
	p, _ := decodePEMFile(privateKey)
	key, err := x509.ParsePKCS8PrivateKey(p)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519 key")
	}
	return PrivateKey(edKey), nil
}

//Sign reads the input file and compute the ED25519 signature
//using the private key.
func (p PrivateKey) Sign(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return "", err
	}
	signature := ed25519.Sign(ed25519.PrivateKey(p), buf)
	return hex.EncodeToString(signature), nil
}

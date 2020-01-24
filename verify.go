package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"os"
)

//PublicKey is ed25519.PublicKey
type PublicKey ed25519.PublicKey

//decodePEMFile reads and decodes generic PEM files.
func decodePEMFile(filePath string) ([]byte, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return nil, err
	}
	p, _ := pem.Decode(buf)
	if p == nil {
		return nil, fmt.Errorf("no pem block found")
	}
	return p.Bytes, nil
}

//GetPublicKey reads the public key from input file and
//returns the initialized PublicKey.
func GetPublicKey(publicKey string) (PublicKey, error) {
	p, _ := decodePEMFile(publicKey)
	key, err := x509.ParsePKIXPublicKey(p)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519 key")
	}
	return PublicKey(edKey), nil
}

//Verify checks that input signature is valid. That is, if
//input file was signed by private key corresponding to input
//public key.
func (p PublicKey) Verify(file, signature string) (bool, error) {
	f, err := os.Open(file)
	if err != nil {
		return false, err
	}
	defer f.Close()
	buf, err := ioutil.ReadAll(f)
	if err != nil {
		return false, err
	}
	byteSign, err := hex.DecodeString(signature)
	if err != nil {
		return false, err
	}
	ok := ed25519.Verify(ed25519.PublicKey(p), buf, byteSign)
	return ok, nil
}

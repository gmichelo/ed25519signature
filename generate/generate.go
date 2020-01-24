package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

const (
	privKeyFile = "key.pem"
	pubKeyFile  = "pub.pem"
)

func main() {
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	//Write public key
	pubOut, err := os.OpenFile(pubKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create %s file: %s", pubKeyFile, err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Unable to marshal public key: %v", err)
	}
	if err := pem.Encode(pubOut, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s file: %s", pubKeyFile, err)
	}
	if err := pubOut.Close(); err != nil {
		log.Fatalf("Error closing %s file: %s", pubKeyFile, err)
	}

	//Write private key
	keyOut, err := os.OpenFile(privKeyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create %s file: %s", privKeyFile, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s file: %s", privKeyFile, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s file: %s", privKeyFile, err)
	}
}

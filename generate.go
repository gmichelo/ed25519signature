package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
)

func generate(private, public string) {
	//GenerateKey will generate the private and public key pairs using
	//rand.Rander as source of entropy
	pubKey, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	//Create file and write public key
	pubOut, err := os.OpenFile(public, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create %s file: %s", private, err)
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		log.Fatalf("Unable to marshal public key: %v", err)
	}
	//Encode public key using PEM format
	if err := pem.Encode(pubOut, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s file: %s", public, err)
	}
	if err := pubOut.Close(); err != nil {
		log.Fatalf("Error closing %s file: %s", public, err)
	}

	//Create file and write private key
	keyOut, err := os.OpenFile(private, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("Failed to create %s file: %s", private, err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		log.Fatalf("Unable to marshal private key: %v", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privBytes,
	}); err != nil {
		log.Fatalf("Failed to write data to %s file: %s", private, err)
	}
	if err := keyOut.Close(); err != nil {
		log.Fatalf("Error closing %s file: %s", private, err)
	}
}

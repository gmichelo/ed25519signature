package main

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
)

func main() {
	flag.Parse()
	log.SetFlags(log.Lshortfile)
	if flag.NArg() != 2 {
		log.Fatal("expected two arguments: private key and file to sign")
	}

	privKey := flag.Arg(0)
	fileToSign := flag.Arg(1)

	key, err := GetPrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}
	signature, err := key.Sign(fileToSign)
	if err != nil {
		log.Fatal(err)
	}
	log.Println(signature)
}

type PrivateKey ed25519.PrivateKey

func GetPrivateKey(privateKey string) (PrivateKey, error) {
	f, err := os.Open(privateKey)
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
	key, err := x509.ParsePKCS8PrivateKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519 key")
	}
	return PrivateKey(edKey), nil
}

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

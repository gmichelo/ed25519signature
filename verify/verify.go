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
	if flag.NArg() != 3 {
		log.Fatal("expected three arguments: public key, file to check and signature")
	}

	pubKey := flag.Arg(0)
	fileToCheck := flag.Arg(1)
	signature := flag.Arg(2)

	pub, err := GetPublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}
	ok, err := pub.Verify(fileToCheck, signature)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		log.Println("valid signature")
	} else {
		log.Println("invalid signature")
	}
}

type PublicKey ed25519.PublicKey

func GetPublicKey(publicKey string) (PublicKey, error) {
	f, err := os.Open(publicKey)
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
	key, err := x509.ParsePKIXPublicKey(p.Bytes)
	if err != nil {
		return nil, err
	}
	edKey, ok := key.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("key is not ed25519 key")
	}
	return PublicKey(edKey), nil
}

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

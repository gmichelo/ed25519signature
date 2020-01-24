package main

import (
	"flag"
	"fmt"
	"log"
	"os"
)

func main() {
	flag.Parse()
	//Expected commands:
	//1) ed25519 sign <key> <file>
	//2) ed25519 verify <pub> <file> <signature>
	//3) ed25519 gen <key> <pub>

	log.SetFlags(log.Lshortfile)
	if flag.NArg() == 0 {
		log.Fatal("missing command: [sign|verify|gen]")
	}
	switch flag.Arg(0) {
	case "sign":
		if flag.NArg() != 3 {
			log.Fatal("command 'sign' requires: <private-key-file> <file-to-sign>")
		}
		key := flag.Arg(1)
		file := flag.Arg(2)
		sign(key, file)
	case "verify":
		if flag.NArg() != 4 {
			log.Fatal("command 'verify' requires: <public-key-file> <file-to-check> <signature>")
		}
		key := flag.Arg(1)
		file := flag.Arg(2)
		signature := flag.Arg(3)
		verify(key, file, signature)
	case "gen":
		if flag.NArg() != 3 {
			log.Fatal("command 'gen' requires: <private-key-file> <public-key-file>")
		}
		key := flag.Arg(1)
		public := flag.Arg(2)
		generate(key, public)
	default:
		log.Fatalf("command %s not supported", flag.Arg(0))
	}
}

func sign(privKey, fileToSign string) {
	//Read the private key
	key, err := GetPrivateKey(privKey)
	if err != nil {
		log.Fatal(err)
	}
	//Compute the signature on the input file
	signature, err := key.Sign(fileToSign)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Signature:", signature)
}

func verify(pubKey, fileToCheck, signature string) {
	//Read the public key
	pub, err := GetPublicKey(pubKey)
	if err != nil {
		log.Fatal(err)
	}
	//Verify if input signature is valid
	ok, err := pub.Verify(fileToCheck, signature)
	if err != nil {
		log.Fatal(err)
	}
	if ok {
		fmt.Println("Valid signature")
		os.Exit(0)
	} else {
		fmt.Println("Invalid signature")
		os.Exit(1)
	}
}

package main

import (
	"log"

	"github.com/jncss/easydsa"
)

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Generate keys
	privateKey := easydsa.GenerateKey(easydsa.L1024N160)
	publicKey := privateKey.GetPublicKey()

	// Text to sign
	text := "DSA signature test!"

	// Sign
	signature, err := privateKey.SignString(easydsa.SHA1, text)
	checkError(err)

	// Verify
	log.Println(publicKey.VerifyString(easydsa.SHA1, text, signature))
}

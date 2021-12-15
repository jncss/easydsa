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

	// Sign
	signature, err := privateKey.SignFile(easydsa.SHA1, "/etc/hosts")
	checkError(err)

	// Verify
	result, err := publicKey.VerifyFile(easydsa.SHA1, "/etc/hosts", signature)
	checkError(err)
	log.Println(result)
}

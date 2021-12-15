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

	// Store keys
	privateKey.Store("./privateDSA.pem")
	publicKey.Store("./publicDSA.pem")

	// Text to sign
	text := "DSA signature test!"

	// Load private key, sign and save signature
	loadedPrivateKey, err := new(easydsa.PrivateKey).Load("privateDSA.pem")
	checkError(err)
	signature, err := loadedPrivateKey.SignString(easydsa.SHA1, text)
	checkError(err)
	signature.Store("./text.sign")

	// Load public key, signature and verify
	loadedPublicKey, err := new(easydsa.PublicKey).Load("publicDSA.pem")
	checkError(err)
	loadedSignature, err := new(easydsa.Signature).Load("./text.sign")
	checkError(err)
	log.Println(loadedPublicKey.VerifyString(easydsa.SHA1, text, loadedSignature))
}

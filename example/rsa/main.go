package main

import (
	"github.com/anantadwi13/ezcrypt"
	"log"
)

func main() {
	keyPair := generateKeyPair()

	printEncodedKey(keyPair)

	cipher := encryptMessage(keyPair, "plain text")
	decryptCipher(keyPair, cipher)
}

func generateKeyPair() ezcrypt.RSAKeyPair {
	keyPair, err := ezcrypt.RsaGenerateKeyPair(ezcrypt.RSAKey2048)
	if err != nil {
		log.Fatalln("error generating key pair", err)
	}
	return keyPair
}

func loadKeyPair(priv []byte) ezcrypt.RSAKeyPair {
	keyPair, err := ezcrypt.RsaLoadEncodedKeyPair(priv)
	if err != nil {
		log.Fatalln("error loading keypair", err)
	}
	return keyPair
}

func printEncodedKey(keyPair ezcrypt.RSAKeyPair) {
	publicKey, err := keyPair.EncodedPublic()
	if err != nil {
		log.Fatalln(err)
	}
	privateKey, err := keyPair.EncodedPrivate()
	if err != nil {
		log.Fatalln(err)
	}

	log.Println()
	log.Println("publicKey", string(publicKey))
	log.Println()
	log.Println("privateKey", string(privateKey))
}

func encryptMessage(keyPair ezcrypt.RSAKeyPair, plainText string) string {
	rsa, err := ezcrypt.RsaOAEPWithSHA512(keyPair)
	if err != nil {
		log.Fatalln("error initializing rsa encryption", err)
	}

	cipherText, err := rsa.EncryptWithPublicKey([]byte(plainText))
	if err != nil {
		log.Fatalln(err)
	}

	log.Println()
	log.Println("cipherText", string(cipherText))
	return string(cipherText)
}

func decryptCipher(keyPair ezcrypt.RSAKeyPair, cipherText string) {
	rsa, err := ezcrypt.RsaOAEPWithSHA512(keyPair)
	if err != nil {
		log.Fatalln("error initializing rsa encryption", err)
	}

	plainText, err := rsa.DecryptWithPrivateKey([]byte(cipherText))
	if err != nil {
		log.Println(err)
	}

	log.Println()
	log.Println("plainText", string(plainText))
}

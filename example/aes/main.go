package main

import (
	"github.com/anantadwi13/ezcrypt"
	"log"
)

func main() {
	aesCBCExample()
	log.Println()
	aesCFBExample()
}

func aesCBCExample() {
	key := ezcrypt.AesGenerateRandomKey(ezcrypt.AESKey256)
	encodedKey, err := key.Encode()
	if err != nil {
		log.Fatalln(err)
	}

	aes, err := ezcrypt.AesCBC(key)
	if err != nil {
		log.Fatalln("error creating aes instance", err)
	}

	cipherText, err := aes.Encrypt([]byte("message length should meet the multiplication of aes.BlockSize (16 bytes). This plaintext contains 112 chars..!!"))
	if err != nil {
		log.Fatalln(err)
	}

	plainText, err := aes.Decrypt(cipherText)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("cbc mode")
	log.Println("encodedKey\t:", string(encodedKey))
	log.Println("cipherText\t:", string(cipherText))
	log.Println("plainText\t:", string(plainText))
}

func aesCFBExample() {
	key := ezcrypt.AesGenerateRandomKey(ezcrypt.AESKey256)
	encodedKey, err := key.Encode()
	if err != nil {
		log.Fatalln(err)
	}

	aes, err := ezcrypt.AesCFB(key)
	if err != nil {
		log.Fatalln("error creating aes instance", err)
	}

	cipherText, err := aes.Encrypt([]byte("there is no message length requirement for this aes encryption mode"))
	if err != nil {
		log.Fatalln(err)
	}

	plainText, err := aes.Decrypt(cipherText)
	if err != nil {
		log.Fatalln(err)
	}

	log.Println("cfb mode")
	log.Println("encodedKey\t:", string(encodedKey))
	log.Println("cipherText\t:", string(cipherText))
	log.Println("plainText\t:", string(plainText))
}

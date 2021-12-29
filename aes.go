package ezcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"io"
)

const (
	AESKey128 = AESKeySize(16)
	AESKey192 = AESKeySize(24)
	AESKey256 = AESKeySize(32)
)

type AESKeySize int

type AES interface {
	SymmetricEncryption
}

type AESKey Key

func (a AESKey) Encode() ([]byte, error) {
	return base64Encode(getBase64Encoder(), a)
}

type aesImpl struct {
	key            AESKey
	b64Encoder     *base64.Encoding
	randReader     io.Reader
	encryptionMode func(dstCipher []byte, blockCipher cipher.Block, srcPlain []byte) error
	decryptionMode func(dstPlain []byte, blockCipher cipher.Block, srcCipher []byte) error
}

func (a *aesImpl) Encrypt(message []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	cipherText := make([]byte, aes.BlockSize+len(message))
	iv := cipherText[:aes.BlockSize]
	_, err = io.ReadFull(a.randReader, iv)
	if err != nil {
		return nil, err
	}

	if a.encryptionMode == nil {
		return nil, errors.New("encryption mode is nil")
	}
	err = a.encryptionMode(cipherText, block, message)
	if err != nil {
		return nil, err
	}

	encodedCipher, err := base64Encode(a.b64Encoder, cipherText)
	if err != nil {
		return nil, err
	}
	return encodedCipher, nil
}

func (a *aesImpl) Decrypt(encodedCipher []byte) ([]byte, error) {
	decodedCipher, err := base64Decode(a.b64Encoder, encodedCipher)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	plainText := make([]byte, len(decodedCipher)-aes.BlockSize)

	if a.decryptionMode == nil {
		return nil, errors.New("decryption mode is nil")
	}
	err = a.decryptionMode(plainText, block, decodedCipher)
	if err != nil {
		return nil, err
	}

	return plainText, nil
}

func (a *aesImpl) Key() Key {
	return Key(a.key)
}

func AesCBC(key AESKey) (AES, error) {
	if key == nil || len(key) <= 0 {
		return nil, errors.New("aes key is nil")
	}
	return &aesImpl{
		key:        key,
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		encryptionMode: func(dstCipher []byte, blockCipher cipher.Block, srcPlain []byte) error {
			if len(dstCipher)%aes.BlockSize != 0 {
				return errors.New("ciphertext is not a multiple of the block size")
			}

			mode := cipher.NewCBCEncrypter(blockCipher, dstCipher[:aes.BlockSize])
			mode.CryptBlocks(dstCipher[aes.BlockSize:], srcPlain)
			return nil
		},
		decryptionMode: func(dstPlain []byte, blockCipher cipher.Block, srcCipher []byte) error {
			if len(srcCipher) < aes.BlockSize {
				return errors.New("ciphertext block size is too short")
			}
			if len(srcCipher)%aes.BlockSize != 0 {
				return errors.New("ciphertext is not a multiple of the block size")
			}

			mode := cipher.NewCBCDecrypter(blockCipher, srcCipher[:aes.BlockSize])
			mode.CryptBlocks(dstPlain, srcCipher[aes.BlockSize:])
			return nil
		},
	}, nil
}

func AesCFB(key AESKey) (AES, error) {
	if key == nil || len(key) <= 0 {
		return nil, errors.New("aes key is nil")
	}
	return &aesImpl{
		key:        key,
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		encryptionMode: func(dstCipher []byte, blockCipher cipher.Block, srcPlain []byte) error {
			stream := cipher.NewCFBEncrypter(blockCipher, dstCipher[:aes.BlockSize])
			stream.XORKeyStream(dstCipher[aes.BlockSize:], srcPlain)
			return nil
		},
		decryptionMode: func(dstPlain []byte, blockCipher cipher.Block, srcCipher []byte) error {
			if len(srcCipher) < aes.BlockSize {
				return errors.New("ciphertext block size is too short")
			}

			stream := cipher.NewCFBDecrypter(blockCipher, srcCipher[:aes.BlockSize])
			stream.XORKeyStream(dstPlain, srcCipher[aes.BlockSize:])
			return nil
		},
	}, nil
}

func AESGenerateRandomKey(keySize AESKeySize) AESKey {
	return generateRandomBytes(int(keySize))
}

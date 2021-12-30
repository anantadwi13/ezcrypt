package ezcrypt

import (
	"bytes"
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

type cipherParams struct {
	block          cipher.Block
	src            []byte
	iv             []byte // initialization vector or nonce
	additionalData []byte
}
type cipherFunc func(params *cipherParams) (dst []byte, err error)

type aesImpl struct {
	key            AESKey
	b64Encoder     *base64.Encoding
	randReader     io.Reader
	ivSize         int    // initialization vector or nonce size
	additionalData []byte // optionally used in GCM mode
	pkcs5Padding   bool
	encryptionMode cipherFunc
	decryptionMode cipherFunc
}

func (a *aesImpl) Encrypt(message []byte) ([]byte, error) {
	block, err := aes.NewCipher(a.key)
	if err != nil {
		return nil, err
	}

	if a.pkcs5Padding {
		padding := block.BlockSize() - len(message)%block.BlockSize()
		padtext := bytes.Repeat([]byte{byte(padding)}, padding)
		message = append(message, padtext...)
	}

	if a.ivSize <= 0 {
		a.ivSize = 0
	}

	params := &cipherParams{
		block:          block,
		src:            message,
		iv:             make([]byte, a.ivSize),
		additionalData: a.additionalData,
	}

	_, err = io.ReadFull(a.randReader, params.iv)
	if err != nil {
		return nil, err
	}

	if a.encryptionMode == nil {
		return nil, errors.New("encryption mode is nil")
	}
	dst, err := a.encryptionMode(params)
	if err != nil {
		return nil, err
	}

	encodedCipher, err := base64Encode(a.b64Encoder, dst)
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

	if a.ivSize <= 0 {
		a.ivSize = 0
	}

	if len(decodedCipher) < block.BlockSize() {
		return nil, errors.New("ciphertext block size is too short")
	}

	params := &cipherParams{
		block:          block,
		src:            decodedCipher,
		iv:             decodedCipher[:a.ivSize],
		additionalData: a.additionalData,
	}

	if a.decryptionMode == nil {
		return nil, errors.New("decryption mode is nil")
	}
	dst, err := a.decryptionMode(params)
	if err != nil {
		return nil, err
	}

	if a.pkcs5Padding {
		padding := dst[len(dst)-1]
		dst = dst[:len(dst)-int(padding)]
	}

	return dst, nil
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
		ivSize:     aes.BlockSize,
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		encryptionMode: func(params *cipherParams) (dst []byte, err error) {
			if len(params.src)%params.block.BlockSize() != 0 {
				return nil, errors.New("plaintext is not a multiple of the block size")
			}

			dst = make([]byte, len(params.iv)+len(params.src))

			mode := cipher.NewCBCEncrypter(params.block, params.iv)
			mode.CryptBlocks(dst[len(params.iv):], params.src)

			for i, b := range params.iv {
				dst[i] = b
			}

			return dst, nil
		},
		decryptionMode: func(params *cipherParams) (dst []byte, err error) {
			if len(params.src)%params.block.BlockSize() != 0 {
				return nil, errors.New("ciphertext is not a multiple of the block size")
			}

			dst = make([]byte, len(params.src)-len(params.iv))

			mode := cipher.NewCBCDecrypter(params.block, params.iv)
			mode.CryptBlocks(dst, params.src[len(params.iv):])

			return dst, nil
		},
	}, nil
}

func AesCBCWithPKCS5Padding(key AESKey) (AES, error) {
	cbc, err := AesCBC(key)
	if err != nil {
		return nil, err
	}
	cbcImpl, _ := cbc.(*aesImpl)
	cbcImpl.pkcs5Padding = true
	return cbcImpl, nil
}

func AesCFB(key AESKey) (AES, error) {
	if key == nil || len(key) <= 0 {
		return nil, errors.New("aes key is nil")
	}
	return &aesImpl{
		key:        key,
		ivSize:     aes.BlockSize,
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		encryptionMode: func(params *cipherParams) (dst []byte, err error) {
			dst = make([]byte, len(params.iv)+len(params.src))

			stream := cipher.NewCFBEncrypter(params.block, params.iv)
			stream.XORKeyStream(dst[len(params.iv):], params.src)

			for i, b := range params.iv {
				dst[i] = b
			}

			return dst, nil
		},
		decryptionMode: func(params *cipherParams) (dst []byte, err error) {
			dst = make([]byte, len(params.src)-len(params.iv))

			stream := cipher.NewCFBDecrypter(params.block, params.iv)
			stream.XORKeyStream(dst, params.src[len(params.iv):])

			return dst, nil
		},
	}, nil
}

// AesGCM return AES with Galois Counter Mode instance. It is using 12 bytes nonce and 16 bytes tag.
// additionalData is an optional parameter (used for authentication purpose). It can be nil or any size slice.
//
// AesGCM.Encrypt will return bytes of base64encode(Nonce+CipherText+Tag).
// AesGCM.Decrypt requires bytes of base64encode(Nonce+CipherText+Tag) parameter.
func AesGCM(key AESKey, additionalData []byte) (AES, error) {
	if key == nil || len(key) <= 0 {
		return nil, errors.New("aes key is nil")
	}
	return &aesImpl{
		key:            key,
		ivSize:         12,
		additionalData: additionalData,
		b64Encoder:     getBase64Encoder(),
		randReader:     getRandomReader(),
		encryptionMode: func(params *cipherParams) (dst []byte, err error) {
			ivSize := len(params.iv)
			dst = make([]byte, ivSize+len(params.src)+16)

			aesgcm, err := cipher.NewGCMWithNonceSize(params.block, ivSize)
			if err != nil {
				return nil, err
			}
			aesgcm.Seal(dst[ivSize:ivSize], params.iv, params.src, params.additionalData)

			copy(dst, params.iv)

			return dst, nil
		},
		decryptionMode: func(params *cipherParams) (dst []byte, err error) {
			aesgcm, err := cipher.NewGCMWithNonceSize(params.block, len(params.iv))
			if err != nil {
				return nil, err
			}
			dst, err = aesgcm.Open(nil, params.iv, params.src[len(params.iv):], params.additionalData)
			if err != nil {
				return nil, err
			}

			return dst, nil
		},
	}, nil
}

func AesGenerateRandomKey(keySize AESKeySize) AESKey {
	return generateRandomBytes(int(keySize))
}

// AesLoadEncodedKey loads encoded base64 key into AESKey
func AesLoadEncodedKey(encodedKey []byte) (AESKey, error) {
	decodedKey, err := base64Decode(getBase64Encoder(), encodedKey)
	if err != nil {
		return nil, err
	}
	return decodedKey, nil
}

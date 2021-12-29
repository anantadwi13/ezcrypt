package ezcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

type AsymmetricEncryption interface {
	EncryptWithPublicKey(message []byte) ([]byte, error)
	DecryptWithPrivateKey(cipher []byte) ([]byte, error)
	KeyPair() KeyPair
}

type KeyPair interface {
	Public() interface{}
	Private() interface{}
	EncodedPublic() ([]byte, error)
	EncodedPrivate() ([]byte, error)
}

var (
	randomReader  = rand.Reader
	base64Encoder = base64.StdEncoding
)

func SetRandomReader(reader io.Reader) error {
	if reader == nil {
		return errors.New("reader is nil")
	}
	randomReader = reader
	return nil
}

func SetBase64Encoder(encoder *base64.Encoding) error {
	if encoder == nil {
		return errors.New("encoder is nil")
	}
	base64Encoder = encoder
	return nil
}

func getRandomReader() io.Reader {
	return randomReader
}

func getBase64Encoder() *base64.Encoding {
	return base64Encoder
}

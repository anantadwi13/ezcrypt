package ezcrypt

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"hash"
	"io"
)

type RSAKeySize int

const (
	RSAKey2048 = RSAKeySize(2048)
	RSAKey4096 = RSAKeySize(4096)
)

type RSA interface {
	AsymmetricEncryption
}

type RSAKeyPair interface {
	KeyPair
	PublicRsa() *rsa.PublicKey
	PrivateRsa() *rsa.PrivateKey
}

type rsaOAEP struct {
	b64Encoder *base64.Encoding
	randReader io.Reader
	hash       hash.Hash
	rsaKeyPair RSAKeyPair
}

func (e *rsaOAEP) EncryptWithPublicKey(message []byte) ([]byte, error) {
	cipherBytes, err := rsa.EncryptOAEP(e.hash, e.randReader, e.rsaKeyPair.PublicRsa(), message, nil)
	if err != nil {
		return nil, err
	}
	return base64Encode(e.b64Encoder, cipherBytes)
}

func (e *rsaOAEP) DecryptWithPrivateKey(cipher []byte) ([]byte, error) {
	if e.rsaKeyPair.PrivateRsa() == nil {
		return nil, errors.New("private key is nil")
	}
	cipherBytes, err := base64Decode(e.b64Encoder, cipher)
	if err != nil {
		return nil, err
	}
	plainBytes, err := rsa.DecryptOAEP(e.hash, e.randReader, e.rsaKeyPair.PrivateRsa(), cipherBytes, nil)
	if err != nil {
		return nil, err
	}
	return plainBytes, nil
}

func (e *rsaOAEP) KeyPair() KeyPair {
	return e.rsaKeyPair
}

func RsaOAEPWithSHA256(keyPair RSAKeyPair) (RSA, error) {
	if keyPair == nil {
		return nil, errors.New("keyPair is nil")
	}
	return &rsaOAEP{
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		hash:       sha256.New(),
		rsaKeyPair: keyPair,
	}, nil
}

func RsaOAEPWithSHA512(keyPair RSAKeyPair) (RSA, error) {
	if keyPair == nil {
		return nil, errors.New("keyPair is nil")
	}
	return &rsaOAEP{
		b64Encoder: getBase64Encoder(),
		randReader: getRandomReader(),
		hash:       sha512.New(),
		rsaKeyPair: keyPair,
	}, nil
}

type rsaKeyPair struct {
	b64Encoder *base64.Encoding
	privKey    *rsa.PrivateKey
	pubKey     *rsa.PublicKey
}

func (r *rsaKeyPair) PublicRsa() *rsa.PublicKey {
	return r.pubKey
}

func (r *rsaKeyPair) PrivateRsa() *rsa.PrivateKey {
	return r.privKey
}

func (r *rsaKeyPair) Public() interface{} {
	return r.pubKey
}

func (r *rsaKeyPair) Private() interface{} {
	if r.privKey == nil {
		return nil
	}
	return r.privKey
}

func (r *rsaKeyPair) EncodedPublic() ([]byte, error) {
	bytes, err := x509.MarshalPKIXPublicKey(r.pubKey)
	if err != nil {
		return nil, err
	}
	return base64Encode(r.b64Encoder, bytes)
}

func (r *rsaKeyPair) EncodedPrivate() ([]byte, error) {
	if r.privKey == nil {
		return nil, errors.New("private key is nil")
	}
	bytes, err := x509.MarshalPKCS8PrivateKey(r.privKey)
	if err != nil {
		return nil, err
	}
	return base64Encode(r.b64Encoder, bytes)
}

func RsaGenerateKeyPair(bits RSAKeySize) (RSAKeyPair, error) {
	privateKey, err := rsa.GenerateKey(getRandomReader(), int(bits))
	if err != nil {
		return nil, err
	}
	return &rsaKeyPair{
		b64Encoder: getBase64Encoder(),
		privKey:    privateKey,
		pubKey:     &privateKey.PublicKey,
	}, nil
}

// RsaLoadEncodedKeyPair loads base64 encoded privateKey into RSAKeyPair.
// It will create RSAKeyPair instance with private and public keys loaded.
func RsaLoadEncodedKeyPair(privateKey []byte) (RSAKeyPair, error) {
	decodedPrivKey, err := base64Decode(getBase64Encoder(), privateKey)
	if err != nil {
		return nil, err
	}

	privKey, err := x509.ParsePKCS8PrivateKey(decodedPrivKey)
	if err != nil {
		return nil, err
	}

	rsaPrivKey, ok := privKey.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key type is not rsa")
	}

	return &rsaKeyPair{
		b64Encoder: getBase64Encoder(),
		privKey:    rsaPrivKey,
		pubKey:     &rsaPrivKey.PublicKey,
	}, nil
}

// RsaLoadEncodedPublicKey loads base64 encoded publicKey only into RSAKeyPair.
// It will create RSAKeyPair instance without a private key.
//
// **NOTE** This RSAKeyPair is used for encryption only.
func RsaLoadEncodedPublicKey(publicKey []byte) (RSAKeyPair, error) {
	decodedPubKey, err := base64Decode(getBase64Encoder(), publicKey)
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(decodedPubKey)
	if err != nil {
		return nil, err
	}

	rsaPubKey, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("public key type is not rsa")
	}

	return &rsaKeyPair{
		b64Encoder: getBase64Encoder(),
		pubKey:     rsaPubKey,
	}, nil
}

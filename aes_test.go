package ezcrypt

import (
	"bytes"
	"crypto/aes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAESGenerateRandomKey(t *testing.T) {
	type args struct {
		keySize AESKeySize
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{keySize: AESKey128},
		},
		{
			name: "success",
			args: args{keySize: AESKey192},
		},
		{
			name: "success",
			args: args{keySize: AESKey256},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := AesGenerateRandomKey(tt.args.keySize)
			assert.Len(t, got, int(tt.args.keySize))
			encoded, err := got.Encode()
			assert.NoError(t, err)
			assert.NotEmpty(t, encoded)
		})
	}
}

func TestGenerate_Encrypt_Decrypt(t *testing.T) {
	type args struct {
		key        AESKey
		aesCreator func(key AESKey) (AES, error)
		message    []byte
	}
	tests := []struct {
		name            string
		args            *args
		encryptModifier func(aesInstance *aesImpl, args *args) error
		decryptModifier func(aesInstance *aesImpl, args *args, cipher *[]byte) error
		wantErrCreator  bool
		wantErrEncrypt  bool
		wantErrDecrypt  bool
	}{
		{
			name: "success cbc 128",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc 192",
			args: &args{
				key:        AesGenerateRandomKey(AESKey192),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc 256",
			args: &args{
				key:        AesGenerateRandomKey(AESKey256),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc + pkcs5 padding 128",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBCWithPKCS5Padding,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc + pkcs5 padding 192",
			args: &args{
				key:        AesGenerateRandomKey(AESKey192),
				aesCreator: AesCBCWithPKCS5Padding,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc + pkcs5 padding 256",
			args: &args{
				key:        AesGenerateRandomKey(AESKey256),
				aesCreator: AesCBCWithPKCS5Padding,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 128",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 192",
			args: &args{
				key:        AesGenerateRandomKey(AESKey192),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 256",
			args: &args{
				key:        AesGenerateRandomKey(AESKey256),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "error cfb nil",
			args: &args{
				key:        nil,
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "success gcm 128",
			args: &args{
				key: AesGenerateRandomKey(AESKey128),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success gcm 192",
			args: &args{
				key: AesGenerateRandomKey(AESKey192),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success gcm 256",
			args: &args{
				key: AesGenerateRandomKey(AESKey256),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "error cfb nil",
			args: &args{
				key:        nil,
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error cbc + pkcs5 padding nil",
			args: &args{
				key:        nil,
				aesCreator: AesCBCWithPKCS5Padding,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error cbc nil",
			args: &args{
				key:        nil,
				aesCreator: AesCBC,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error gcm nil",
			args: &args{
				key: nil,
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error cbc message block not a multiple of aes.BlockSize",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize-1],
			},
			wantErrEncrypt: true,
			wantErrDecrypt: false,
		},
		{
			name: "error encrypt invalid keySize",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			encryptModifier: func(aesInstance *aesImpl, args *args) error {
				aesInstance.key = nil
				return nil
			},
			wantErrEncrypt: true,
		},
		{
			name: "error encrypt read iv",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			encryptModifier: func(aesInstance *aesImpl, args *args) error {
				aesInstance.randReader = &bytes.Buffer{}
				return nil
			},
			wantErrEncrypt: true,
		},
		{
			name: "error encrypt nil encryption mode",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			encryptModifier: func(aesInstance *aesImpl, args *args) error {
				aesInstance.encryptionMode = nil
				return nil
			},
			wantErrEncrypt: true,
		},
		{
			name: "error encrypt base64 encoder",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			encryptModifier: func(aesInstance *aesImpl, args *args) error {
				aesInstance.b64Encoder = nil
				return nil
			},
			wantErrEncrypt: true,
		},
		{
			name: "error decrypt invalid keySize",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				aesInstance.key = nil
				return nil
			},
			wantErrDecrypt: true,
		},
		{
			name: "error decrypt invalid cipher",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				*cipher = []byte{}
				return nil
			},
			wantErrDecrypt: true,
		},
		{
			name: "error decrypt invalid cipher",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				*cipher = []byte("MTIzNDU2NzgxMjM0NTY3ODE=")
				return nil
			},
			wantErrDecrypt: true,
		},
		{
			name: "error decrypt nil decryption mode",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				aesInstance.decryptionMode = nil
				return nil
			},
			wantErrDecrypt: true,
		},
		{
			name: "error decrypt base64 encoder",
			args: &args{
				key:        AesGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    []byte("exampleplaintext"),
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				aesInstance.b64Encoder = nil
				return nil
			},
			wantErrDecrypt: true,
		},
		{
			name: "error gcm invalid nonce size encryption",
			args: &args{
				key: AesGenerateRandomKey(AESKey128),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			encryptModifier: func(aesInstance *aesImpl, args *args) error {
				aesInstance.ivSize = 0
				return nil
			},
			wantErrEncrypt: true,
			wantErrDecrypt: false,
		},
		{
			name: "error gcm invalid nonce size decrypt",
			args: &args{
				key: AesGenerateRandomKey(AESKey128),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				aesInstance.ivSize = 0
				return nil
			},
			wantErrEncrypt: false,
			wantErrDecrypt: true,
		},
		{
			name: "error gcm authentication failed",
			args: &args{
				key: AesGenerateRandomKey(AESKey128),
				aesCreator: func(key AESKey) (AES, error) {
					return AesGCM(key, nil)
				},
				message: lipsum,
			},
			decryptModifier: func(aesInstance *aesImpl, args *args, cipher *[]byte) error {
				aesInstance.additionalData = []byte("change")
				return nil
			},
			wantErrEncrypt: false,
			wantErrDecrypt: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			aesType, err := tt.args.aesCreator(tt.args.key)
			if (err != nil) != tt.wantErrCreator {
				t.Errorf("aesCreator() error = %v, wantErr %v", err, tt.wantErrCreator)
				return
			}
			if tt.wantErrCreator {
				return
			}
			assert.NotNil(t, aesType)
			assert.NotNil(t, aesType.Key())

			if tt.encryptModifier != nil {
				aesInstance, ok := aesType.(*aesImpl)
				assert.True(t, ok)
				err = tt.encryptModifier(aesInstance, tt.args)
				assert.NoError(t, err)
			}

			cipherText, err := aesType.Encrypt(tt.args.message)
			if (err != nil) != tt.wantErrEncrypt {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErrEncrypt)
				return
			}
			if tt.wantErrEncrypt {
				return
			}
			assert.NotEmpty(t, cipherText)

			if tt.decryptModifier != nil {
				aesInstance, ok := aesType.(*aesImpl)
				assert.True(t, ok)
				err = tt.decryptModifier(aesInstance, tt.args, &cipherText)
				assert.NoError(t, err)
			}

			plainText, err := aesType.Decrypt(cipherText)
			if (err != nil) != tt.wantErrDecrypt {
				t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErrDecrypt)
				return
			}
			if tt.wantErrDecrypt {
				return
			}
			assert.Equal(t, tt.args.message, plainText)
		})
	}
}

func TestAESLoadEncodedKey(t *testing.T) {
	type args struct {
		keySize    AESKeySize
		encodedKey []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success 128",
			args: args{
				keySize: AESKey128,
				encodedKey: []byte{
					65, 119, 50, 119, 90, 122, 97, 89, 73, 103, 76, 109, 54, 105, 66, 66, 108, 114, 71, 103, 69, 81, 61,
					61,
				},
			},
			wantErr: false,
		},
		{
			name: "success 192",
			args: args{
				keySize: AESKey192,
				encodedKey: []byte{
					83, 83, 54, 110, 80, 108, 107, 54, 47, 73, 118, 57, 88, 110, 111, 69, 65, 99, 86, 82, 68, 79, 87,
					82, 85, 106, 49, 119, 89, 75, 53, 118,
				},
			},
			wantErr: false,
		},
		{
			name: "success 256",
			args: args{
				keySize: AESKey256,
				encodedKey: []byte{
					122, 87, 80, 52, 115, 73, 87, 86, 98, 108, 57, 104, 116, 102, 100, 107, 122, 100, 98, 55, 55, 89,
					78, 72, 106, 117, 110, 85, 78, 80, 49, 81, 117, 121, 101, 122, 72, 103, 104, 77, 88, 68, 107, 61,
				},
			},
			wantErr: false,
		},
		{
			name:    "success empty",
			args:    args{encodedKey: []byte{}},
			wantErr: false,
		},
		{
			name: "error invalid base64",
			args: args{
				keySize: AESKey128,
				encodedKey: []byte{
					0, 119, 50, 119, 90, 122, 97, 89, 73, 103, 76, 109, 54, 105, 66, 66, 108, 114, 71, 103, 69, 81, 61,
					61,
				},
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := AesLoadEncodedKey(tt.args.encodedKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("AesLoadEncodedKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.Len(t, got, int(tt.args.keySize))
			encodedKey, err := got.Encode()
			assert.NoError(t, err)
			assert.Equal(t, tt.args.encodedKey, encodedKey)
		})
	}
}

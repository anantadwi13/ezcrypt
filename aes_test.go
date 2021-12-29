package ezcrypt

import (
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
			got := AESGenerateRandomKey(tt.args.keySize)
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
		name           string
		args           args
		wantErrCreator bool
		wantErrEncrypt bool
		wantErrDecrypt bool
	}{
		{
			name: "success cbc 128",
			args: args{
				key:        AESGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc 192",
			args: args{
				key:        AESGenerateRandomKey(AESKey192),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cbc 256",
			args: args{
				key:        AESGenerateRandomKey(AESKey256),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize],
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 128",
			args: args{
				key:        AESGenerateRandomKey(AESKey128),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 192",
			args: args{
				key:        AESGenerateRandomKey(AESKey192),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "success cfb 256",
			args: args{
				key:        AESGenerateRandomKey(AESKey256),
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrEncrypt: false,
			wantErrDecrypt: false,
		},
		{
			name: "error cfb nil",
			args: args{
				key:        nil,
				aesCreator: AesCFB,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error cbc nil",
			args: args{
				key:        nil,
				aesCreator: AesCBC,
				message:    lipsum,
			},
			wantErrCreator: true,
		},
		{
			name: "error cbc message block not a multiple of aes.BlockSize",
			args: args{
				key:        AESGenerateRandomKey(AESKey128),
				aesCreator: AesCBC,
				message:    lipsum[:len(lipsum)/aes.BlockSize*aes.BlockSize-1],
			},
			wantErrEncrypt: true,
			wantErrDecrypt: false,
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

			cipherText, err := aesType.Encrypt(tt.args.message)
			if (err != nil) != tt.wantErrEncrypt {
				t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErrEncrypt)
				return
			}
			if tt.wantErrEncrypt {
				return
			}
			assert.NotEmpty(t, cipherText)

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

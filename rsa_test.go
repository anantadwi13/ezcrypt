package ezcrypt

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestRsaGenerateKeyPair(t *testing.T) {
	type args struct {
		bits RSAKeySize
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				bits: RSAKey2048,
			},
			wantErr: false,
		},
		{
			name: "success 2",
			args: args{
				bits: RSAKey4096,
			},
			wantErr: false,
		},
		{
			name: "error",
			args: args{
				bits: 0,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaGenerateKeyPair(tt.args.bits)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaGenerateKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotNil(t, got)
			assert.NotNil(t, got.PrivateRsa())
			assert.NotNil(t, got.PublicRsa())
			assert.NotNil(t, got.Private())
			assert.NotNil(t, got.Public())
			assert.IsType(t, &rsa.PrivateKey{}, got.Private())
			assert.IsType(t, &rsa.PublicKey{}, got.Public())
			encodedPublic, err := got.EncodedPublic()
			assert.NoError(t, err)
			assert.NotEmpty(t, encodedPublic)
			encodedPrivate, err := got.EncodedPrivate()
			assert.NoError(t, err)
			assert.NotEmpty(t, encodedPrivate)
		})
	}
}

func TestRsaOAEPWithSHA256(t *testing.T) {
	keyPair, err := RsaGenerateKeyPair(RSAKey2048)
	assert.NoError(t, err)
	tests := []struct {
		name    string
		arg     RSAKeyPair
		wantErr bool
	}{
		{
			name:    "success",
			arg:     keyPair,
			wantErr: false,
		},
		{
			name:    "error",
			arg:     nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaOAEPWithSHA256(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaOAEPWithSHA256() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.KeyPair())
		})
	}
}

func TestRsaOAEPWithSHA512(t *testing.T) {
	keyPair, err := RsaGenerateKeyPair(RSAKey2048)
	assert.NoError(t, err)
	tests := []struct {
		name    string
		arg     RSAKeyPair
		wantErr bool
	}{
		{
			name:    "success",
			arg:     keyPair,
			wantErr: false,
		},
		{
			name:    "error",
			arg:     nil,
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaOAEPWithSHA512(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaOAEPWithSHA512() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.KeyPair())
		})
	}
}

func Test_rsaOAEP_Encrypt(t *testing.T) {
	keyPair2048, err := RsaGenerateKeyPair(RSAKey2048)
	assert.NoError(t, err)
	keyPair4096, err := RsaGenerateKeyPair(RSAKey4096)
	assert.NoError(t, err)

	lipsum := "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros in gravida pulvinar, urna metus rhoncus tellus, vitae fringilla odio sem sit amet est. Donec tincidunt, orci ut sodales tempor, orci urna vehicula turpis, ut mollis turpis quam in est. Integer eros neque, sodales in elit vitae, sagittis maximus metus. Maecenas sit amet sollicitudin arcu, nec ullamcorper nulla massa nunc."

	type args struct {
		message []byte
	}
	tests := []struct {
		name        string
		rsaInstance RSA
		args        args
		wantErr     bool
	}{
		{
			name: "success",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte("")},
			wantErr: false,
		},
		{
			name: "success 2",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte("okay")},
			wantErr: false,
		},
		{
			name: "success 3 rsa oaep sha256 key2048 190 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:190])},
			wantErr: false,
		},
		{
			name: "success 4 rsa oaep sha512 key2048 126 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA512(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:126])},
			wantErr: false,
		},
		{
			name: "success 5 rsa oaep sha256 key4096 446 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair4096)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:446])},
			wantErr: false,
		},
		{
			name: "success 6 rsa oaep sha512 key4096 382 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA512(keyPair4096)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:382])},
			wantErr: false,
		},
		{
			name: "error rsa oaep sha256 key2048 191 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:191])},
			wantErr: true,
		},
		{
			name: "error rsa oaep sha512 key2048 127 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA512(keyPair2048)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:127])},
			wantErr: true,
		},
		{
			name: "error rsa oaep sha256 key4096 447 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA256(keyPair4096)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:447])},
			wantErr: true,
		},
		{
			name: "error rsa oaep sha512 key4096 382 chars",
			rsaInstance: func() RSA {
				rsaOAEPSHA256, err := RsaOAEPWithSHA512(keyPair4096)
				assert.NoError(t, err)
				return rsaOAEPSHA256
			}(),
			args:    args{message: []byte(lipsum[:383])},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cipherText, err := tt.rsaInstance.EncryptWithPublicKey(tt.args.message)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptWithPublicKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotEmpty(t, cipherText)

			plainText, err := tt.rsaInstance.DecryptWithPrivateKey(cipherText)
			assert.NoError(t, err)
			assert.Equal(t, tt.args.message, plainText)

			//pubKey, err := tt.rsaInstance.KeyPair().EncodedPublic()
			//assert.NoError(t, err)
			//privKey, err := tt.rsaInstance.KeyPair().EncodedPrivate()
			//assert.NoError(t, err)
			//log.Println("public", string(pubKey))
			//log.Println("private", string(privKey))
			//log.Println("cipher", string(cipherText))
			//log.Println("plain", string(plainText))
		})
	}
}

func Test_rsaOAEP_DecryptWithPrivateKey(t *testing.T) {
	type args struct {
		pubKey  []byte
		privKey []byte
		cipher  []byte
		plain   []byte
	}
	tests := []struct {
		name       string
		rsaFactory func(keyPair RSAKeyPair) (RSA, error)
		args       args
		wantErr    bool
	}{
		{
			name:       "success rsa oaep sha256 key2048",
			rsaFactory: RsaOAEPWithSHA256,
			args: args{
				pubKey:  []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvDmplJ5hbjlBdPr+3iWtG3X/3/ZPiOYns4AECCf3xInnhAfnGrh9CJCiTtQAydjT95UEIP9SHUuYz1R9LQfgXv6wTfpwyaJ9otB71xJ6gGD0y24LD0sVj4T+QmpF3w/xI6fIZNYNKVjMb/vkSN9snnpTEHlFuI/upiVV765t7CkCgAafqbLTjJejsH0YtPPzPfVTQwVUu1wnv1behZuQ9gTu/ueZYdi9SbkZT8z2GPVvCZjx/WGx4ivumM9b3tstCEyOnTRKWYR4sZSR3wkW+HzocXRTzTvBNZ7RnhSGfp1XBbtLPI+h+PXNSUxCQMUKCwKjeJvnpdENgE8ZHW1yQIDAQAB"),
				privKey: []byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDG8OamUnmFuOUF0+v7eJa0bdf/f9k+I5iezgAQIJ/fEieeEB+cauH0IkKJO1ADJ2NP3lQQg/1IdS5jPVH0tB+Be/rBN+nDJon2i0HvXEnqAYPTLbgsPSxWPhP5CakXfD/Ejp8hk1g0pWMxv++RI32yeelMQeUW4j+6mJVXvrm3sKQKABp+pstOMl6OwfRi08/M99VNDBVS7XCe/Vt6Fm5D2BO7+55lh2L1JuRlPzPYY9W8JmPH9YbHiK+6Yz1ve2y0ITI6dNEpZhHixlJHfCRb4fOhxdFPNO8E1ntGeFIZ+nVcFu0s8j6H49c1JTEJAxQoLAqN4m+el0Q2ATxkdbXJAgMBAAECggEAEmU8Lqz5p6/NHZjW/U3NQanWiz2bLO/FsQmDX/pkThAzsZ30DlajxhtU47OkVmZR/JSmWVCbHxQW0f5dka8GKsb4DN3Ks8zgfPerhSKXgxfYxLI5kX2ml+Ltnd2S0SUgEGDPvh8NzPBuF6+Ty2vot5QmSnLdaBxLoElzpcVxDtcQ0X0Z7IdYyyUqvIGlHBWKvlgPRTNRwLLaLULNFWy40MyvlGiEm5uGZZ3mlM2V22MD1JEF7nhoewSH4MLvpoB/aiZuWGQCgTqGQTy9T9z7VQIl2t3N6xqAxnulBAO+D14nwzocDC3AMVoVv8TPcYKVJFJ0L1Y+XNxoQhzptLfmwQKBgQDaEBoUV5jv0TqIX3zyhyHDIQs6zLOfQFr2E2eSjRftTGw64hNUXWFwnKhcLWXx21hZTndAzKZVU/1fz6v5/Qfopl7By7l3tGnC+7JGUzJl3RVxjwgqofEISLuyFRqr2cvujuLuWuxfZBNQ8vHc+G8dDYFuZwh+qlNVa8yo5wNk3QKBgQDpjSpQxYAy6bTXon7l52lwX22iOJcG4o6jxVV5f0B6pmr8dYft7yJQP6Rf4y8nlkUj5vk2RDViT1clHHH3LYCddRhtcNQ8VzPBJB8Xa1Hjlg4egMJZaoBmcI3hXvUiUT1DqMtCpwbeq76mn7ShBSvDcYmjV5VDymk6uRbYBpZ/3QKBgQCGlkOSZJJXCbrnqo/SnIbBCWcF7ou6cZzynf1h3UV0R6PRH/GwM0ZNm9LpuXdfM/Mug5hk3SqYJZOPi/xn+bzk4bJASD37XNWd630XnIfRiQeQJCh1L6g1Zba67f2dLXqJjZUQafvT0E9/ucJ/kLH7q3dELcF3dCak5TjW0mYs3QKBgFHPlkwW8vJitWt3y3XjWyb29qOFqTnLMOYjYO6facnM89sdnJD3XJC5ym2gWktGs0+BQDkHKaAXZNJmJXHNaak+dGEZze6ZKVL1wUJl4JiVXrrGpc3GpdW8haa1qa7swEYsIY9mjNyBUtZxSUfCVPMwmWMzceD+TWA5p8vieuOtAoGAO5AW9XEWL22nm7Juro0RfFa7T3S8vvef4cFtrkT6mxbInAFfk8Ld++vozlU2vQuniYzRb9/mwdPsVE4dhXIMWzuLcg1aPV85gsIdE2VAqX1eAkZ1Sk/Jx0vsO/ooWaGzBM75+O1DLwq5LqtgoVAF5ZZaew7SUGXYI/7U55Kg1xs="),
				cipher:  []byte("iqzLFa6rOPRj4LJRqT7ZStD0hBiWrBB8nzo7IegiB8dceT7phmu1+xfHeRWD0rSKfXfc2O1oGBOjZOA593fsn7+q+xud5l08PJQOyuto/Qq8cg7kHyuq4aivNAu/P9gjsvPlghkeDRMAF7IMtBnBBHuR9wVvsWucVN/iuZTggLZ6gPhxw5fufuf29LslCLkIC+PSXZD71KdQAWDxrls/MHJwdEF1H6KVZeNbBQJwaKuESYibDg6ohlo9oejX1OW5bahfoX7RkOQW64q3JvYY/WPnyH4AAETkwoWaUxgH4/vBvl7qMlEZqQKcXZWPmcS3M14uzQ8+Lgp2ClkEfDR5wQ=="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros "),
			},
			wantErr: false,
		},
		{
			name:       "success rsa oaep sha512 key2048",
			rsaFactory: RsaOAEPWithSHA512,
			args: args{
				pubKey:  []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAr0GDMhLaZ/+66zDFziSwal1BrGiuab/wRsHf0SKXxOf1IKrl5XcL0OrXxbjgDfDOfO1HwjE4QVhG2icjRxDBO4O+mpFpNXHepoXt0nAlMMxp4X2P/7z2nl8gHwgL1jAhnzJ3QYGTNDAAqulsZCU5/oJQtRgoJ+/pPsKCJQ5c4f7Ukuxa+x3FE7S52AOm6oeF0vaWPO8hJi0++sZNjKVMuFbyjEvMYUqsdPu1CrfYtj4LjXEDI6AuVUoxo5IVysopXlf6XJxaioMZGCrhoCglteJCReTRXMSK+fT0i0kM1HdicrdqAwx/jcQZP1IC9lGRFEJPEchjtU5ZaVpUx4AIfQIDAQAB"),
				privKey: []byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCvQYMyEtpn/7rrMMXOJLBqXUGsaK5pv/BGwd/RIpfE5/UgquXldwvQ6tfFuOAN8M587UfCMThBWEbaJyNHEME7g76akWk1cd6mhe3ScCUwzGnhfY//vPaeXyAfCAvWMCGfMndBgZM0MACq6WxkJTn+glC1GCgn7+k+woIlDlzh/tSS7Fr7HcUTtLnYA6bqh4XS9pY87yEmLT76xk2MpUy4VvKMS8xhSqx0+7UKt9i2PguNcQMjoC5VSjGjkhXKyileV/pcnFqKgxkYKuGgKCW14kJF5NFcxIr59PSLSQzUd2Jyt2oDDH+NxBk/UgL2UZEUQk8RyGO1TllpWlTHgAh9AgMBAAECggEBAIGgeUOeQkFOG5k+F/CjnoDtvVeije7V8wjC+aMcbRlNYDfrb+PLq8e5DCPI3KAzDufEMaFm+m8Ktk1BSYyUzfgRN/fnueO397E/umo+XKO9bktEri/AOsFlJsMNFoQ0UYoIr8CZ8KFXKAdCY9Om3UBsbvmjhoATqXesMsrp1rWopy4y7vNRjIsjPCdpe2RN1fAX7JIjZ/HIvHKCa5FeMWF+RgMpk6HrtIbBMa+8s6l/YGlGS1F02uYQvZOfx3mjB4AjCFLTNHOj/sapbjWzuyjnruJbOmFRY75XHTkyBudfIUN6jt6zRABb9OqBhVcM+A0RCItC0RQgoyT5Uzg6mUECgYEA3g4ldxnkqmdGskH3D1tzWAbvhACr/gQS+Yhvax9/FB1WT69paQAOSIXSkAZKCxgLBYyVP3SNsw3dU+UvKWUb5EAqhIcBdBglenWJPjlkJVXxbZeUO2GjGUl9NRuWP2LoFBd/iaz5LxYMKUc63atguZbV9OFTrLFGVoYD9u8VEPUCgYEAygvurCl3jLOB/FVzolrSASEOLRsQm0CwCKdWNUSiIoK7ZFYskvSS5M2duslk0VsiJTDJZ2QpujnP8WthVVD0aJygm9ap7yqynODih2JRtk7gyaSeMbhbSd7ig7RblqucQI8EXKCia4p88Jmz7HQh4zbGxKgGdpHdPNBoOf0PRGkCgYAp9cJenyX2jU1uochtvnotSCI6b2YQufRb8swbEfiRdHm61Qq2LKyGR8NiM84KCqEKi2Yod33PN+96yvP+fnymxPlD0b8UkPuECHHGsFGcPIFClEIOdoS7YoemYXAiyi3QniAbg/QSUbg6lJsrCBde+oGzpGCLYXRJJUnaf5MbgQKBgEM9KVaeDi0C6DVDctILC2xYxdD4+tPP+UVH+waLKrH1c8t2aisVvXTrgJxSvXx2qaxaygvgZ4qUBsG/DItJ/6x4w3JZRABV408WAA0yCSN0qJYydHrzcV3qENPnx7sirUNG1RrGUocbdWzUme4Mz+I/rnJvwIbhEBFXAfiaYORRAoGALyOcnt0/TAoqvwt+9JByd+2ZFF3zLPp5a7OhX96HJ6dl6zKBBjALS2DRovp6B2p43E13kyviX/qG1x0pxmTDvx9F38kIcG/WB/Ry5W0vuPNJ9Hc8O0qi7Xgv4az+9zgp9taORT/ijevXr6+EqSnbD91kX0bfFHdhz2O054y2aME="),
				cipher:  []byte("UfIvhBvp52Cr5Cxf9/KHY+YxssLFYHsSbaWWRZLcmKzIZr+/bVzMgD3pV5nH+M/bC8t+UJxxTvxO+p3g44bai83l2/o8+Uav4RV2KTMzf3cPteCzn3kvjPEkboeryyqt3a4YKmSPyZv27roSHgxFPxtrDxkv0n9wSq5MteoPFIO7qsO8PxDbu8FK0KKyYZvloys/r85YPwb3GJjWSXhAvftFijNhWNgKFORiZ/Y7FTgdQ+mSAb2qQj9npf9sDqxNkYxP4B4mrRNM/nfmbWw8FxP+xhqLJJ5sYWjohI8Ew8Nw+pASPj9Tp5+cem7RFFBXhrUP6Gkf7MmmTEybUJXNuw=="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam "),
			},
			wantErr: false,
		},
		{
			name:       "success rsa oaep sha256 key4096",
			rsaFactory: RsaOAEPWithSHA256,
			args: args{
				pubKey:  []byte("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAslJWQjpGuHprvt/NKI2jE4rEQKqZlsgiWf78E0vnRzEKbJ7SFfgX2F/YOgJNzHppcGTofh+sgFLouaosGothBQTvgDX3S4QapQVyFgrp0EP9WXiipoAd9QIZfc9/mwAFJIy4GrcqNuC0fwWq2q0OmNIwZ/7VbFFvGb2BPKOcw9BlmvYoW0n2hHnrptSP+y9Rd4VF3eZRDPnFW9mhEL17UU1XOWwudpCVOG6sR9gf1ycNRsKQzxbYFc++GYP2rYg6c0YRdFdWwkgxSEC3HX0zLIMIktMv8EzbNtHf9FFwbKZExjL92rRVO46bs/vjgCV86n5uXGYzI6kRcHvKajrjzg9N5b6qo5cJp6bHiS8gmdqDig3JSBhHicOubx2Os+txc3GzLL1IZLTBtywzmkULk9AXRRBFyzjq3y13MLpIuTWdMHoi31ICm9D59vnE5KgodQFARtlNU/r7ccYc5tYQinwfI1APcxt/7FUTEHqkFPyKTRL5rgcoObkoC8TbKkPAsdDdvEflGVPxN/DXcKeE4su604o20CyBCpx8L05VYeRHyHUwmWjvmsTVBpLug7GaXFocKrO1yqa1v4l3Ppmqq83dHvJ2Izib+fkYnedwovjactgm29e7XYmgSP6LS0pZsPdciqOmsIlRkSX6snMD1L3tVr0ud3m6VztDibwsXscCAwEAAQ=="),
				privKey: []byte("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"),
				cipher:  []byte("WIBS6WqFs3p5Tha87QNT+kDrgKTAqTJbQIyNBAoC8nYHiQG4PJLpjNUkNVLFWzN5BpePHXI0/L2JZE5Z07ek2D3jZ5D2ENo2RsF35js3A/d/77POart9TWRrcTw4Wp/134MDdkUFKwRWI/T74aNTVdd2iW+HW2HrBva3LrKYRiebSfrSR5cnSuE9K81TV3oYMBmk5nr9ljBE2paPt1UQBY/4ZH9diDCUJvALAk8rOxy0eT/KRstwjVXHtrRMWYRJU3V5Tkhh046yLZK8wBSE1p27Eeswki/FPSNOfJfSFh/Pmpeh7hmmjIubHrVjOqSnElY90znY4I0pPBmPFWZB9zaexZ8YyBkJyc7fBLIpz7N6nbSXOsxzdlcFJSHngnN+HBxzzkBq8Iyc2wo9n2IhG74NNm6Y5mI3Qf+XvnCxw6PDnP3Oydrh7EVHmkn8SDMcueEd+zhCbs2xJjKxy/xO9wbYdbysRN3Km/8T0dgQ0zNYIepQBFAfgeIVcWVA/q7dvDo09HWY6wi96PNZBUHM/X4GKFB8gYjR0h+AKRE+kdRiO4oqIpgDVx8C+T8nS5oGbqn1O+AshdRjz5vo6BAza8BQXLLPDyuKNO1dElMctYy8FOETIdyMpSiAfKazmtFcz+WK1tQYqL8rbeNl/OT3Qzu33yZxyY/e8ht9xipECN4="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros in gravida pulvinar, urna metus rhoncus tellus, vitae fringilla odio sem sit amet est. Donec tincidunt, orci ut sodales tempor, orci urna vehicula turpis, ut mollis turpis quam in est. Integer eros neque, sodales in elit vitae, sagittis maximus metus. Maec"),
			},
			wantErr: false,
		},
		{
			name:       "success rsa oaep sha512 key4096",
			rsaFactory: RsaOAEPWithSHA512,
			args: args{
				pubKey:  []byte("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEArnSnUAyHyL1/2Zug8poF11ja7neujIkcMWARlgnGJxzRvsuj6sBH9X5o7Hu+wgOuGhSecTkFYma22G6wTIHilTtHNJPDOzPYRZJKpAW0Px7HVMIoXN1NRkSZEczksaYNFB7tkg/Q0JjfD53hqXc25Uyj/BJJgI4HH+PnVzxE7o1yxnFYvDaXzWz4vlyrZA7Jrugd6c37d2qTT84qzLZNVYQmA+bDqDjsTI9t/kWn5WfExJiX2Sw2fF9QrLod4OqSMc5F+LWwvbOm6J4uyKm6JvgPXMTpEW9Pr3oPnaDz+ofpjpCLLEcxhIbNtSlGXgMSteqiqc3thT+fdT2caXRW750wD8+uZ6Dd60mxsvalunMu1x6f057kS4pZCj4yOUcU2TXnpWaP9i1gjnOahrw3egeWt3tY8lPpztEMNGAPXnevSV6CNJQAFxbJpILfkcPjyJiazfMwUJc0sc8GrYUDdBNXCWNnyBGJA1EgTSJAdpuvSeOIOn75mpgiy2h6/2YrwL3Kb/TG8x0TM/MXHfbCCXstLpOgWe0T+1qjpRz7sF8rz1+HmL2/LwxxySOW9za4xppqmrzAnwAYOVYIR56vT0oEp44VfO/Uc2EZDx8qYyxStqDLR4Mk3/hPBD+mdleFf0Frd5rumWe275BRRqBkZSq4UvqQ0gCbhnHEeu56RuECAwEAAQ=="),
				privKey: []byte("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"),
				cipher:  []byte("qQOy3/ZsX8vUX9+UocM0Za0uAJGxN4P+2AJPN1EFR9wqgC/4m5LISrA0dPsdL/KEGrOpTTCiCluGnaZhvzW9KWCWW9dNL2tVxip5aJ/dgZNKJ5hpqZjXSCG+zNMT0JicamzB20z2TgR9YtsWy94UsbeR+wPnGgFX6+ZotQYMhnmu3VHuDSEap/K3JL1/GR/S3fYINtQwxYOfCLkJknOIO786C58fP+AdS7o4nKqPajTcpE3r3m5GRbbwhrQnVYBWty/l/qRvbeJPdyxeFvhvSya2P8wpd/cxOus4RqxT51wdKw3kVdxGCszgWdk4YJ/CaqbLLzeANiTED8PHq85xQPq8NkbXDrM/5PkdRuS34rEtrEd0luaAlxpDkZf3U9rsupHxnL3dtu3cyNhWX0MNNM6E2JxXOmCCMgy0L9xi2JTnSprOlgNGPBk6p27OOyq/lyL136ww/j1CgXwSdGyL2za5P13ulISzlZov6jctg7/lpwcHRb+uKRGSgWsDOab/OBOUGFmBweMP88n4AMmV4o8Q59kMnRAhU5NwaoCv8CHvFFg7MZHLsgMZwPu2wflR/uwOVmsNDitJlZS8abYtyKZ5GJk2OlY3q5jkV3I7J9u5zN8dKJOrazmUYaJU+NaLmAH6n1MX8p7jRPQwulZvm5G1LMaf8cMT8es5b5CkcEQ="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros in gravida pulvinar, urna metus rhoncus tellus, vitae fringilla odio sem sit amet est. Donec tincidunt, orci ut sodales tempor, orci urna vehicula turpis, ut mollis turpis quam in est. Integer"),
			},
			wantErr: false,
		},
		{
			name:       "error base64",
			rsaFactory: RsaOAEPWithSHA256,
			args: args{
				pubKey:  []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvDmplJ5hbjlBdPr+3iWtG3X/3/ZPiOYns4AECCf3xInnhAfnGrh9CJCiTtQAydjT95UEIP9SHUuYz1R9LQfgXv6wTfpwyaJ9otB71xJ6gGD0y24LD0sVj4T+QmpF3w/xI6fIZNYNKVjMb/vkSN9snnpTEHlFuI/upiVV765t7CkCgAafqbLTjJejsH0YtPPzPfVTQwVUu1wnv1behZuQ9gTu/ueZYdi9SbkZT8z2GPVvCZjx/WGx4ivumM9b3tstCEyOnTRKWYR4sZSR3wkW+HzocXRTzTvBNZ7RnhSGfp1XBbtLPI+h+PXNSUxCQMUKCwKjeJvnpdENgE8ZHW1yQIDAQAB"),
				privKey: []byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDG8OamUnmFuOUF0+v7eJa0bdf/f9k+I5iezgAQIJ/fEieeEB+cauH0IkKJO1ADJ2NP3lQQg/1IdS5jPVH0tB+Be/rBN+nDJon2i0HvXEnqAYPTLbgsPSxWPhP5CakXfD/Ejp8hk1g0pWMxv++RI32yeelMQeUW4j+6mJVXvrm3sKQKABp+pstOMl6OwfRi08/M99VNDBVS7XCe/Vt6Fm5D2BO7+55lh2L1JuRlPzPYY9W8JmPH9YbHiK+6Yz1ve2y0ITI6dNEpZhHixlJHfCRb4fOhxdFPNO8E1ntGeFIZ+nVcFu0s8j6H49c1JTEJAxQoLAqN4m+el0Q2ATxkdbXJAgMBAAECggEAEmU8Lqz5p6/NHZjW/U3NQanWiz2bLO/FsQmDX/pkThAzsZ30DlajxhtU47OkVmZR/JSmWVCbHxQW0f5dka8GKsb4DN3Ks8zgfPerhSKXgxfYxLI5kX2ml+Ltnd2S0SUgEGDPvh8NzPBuF6+Ty2vot5QmSnLdaBxLoElzpcVxDtcQ0X0Z7IdYyyUqvIGlHBWKvlgPRTNRwLLaLULNFWy40MyvlGiEm5uGZZ3mlM2V22MD1JEF7nhoewSH4MLvpoB/aiZuWGQCgTqGQTy9T9z7VQIl2t3N6xqAxnulBAO+D14nwzocDC3AMVoVv8TPcYKVJFJ0L1Y+XNxoQhzptLfmwQKBgQDaEBoUV5jv0TqIX3zyhyHDIQs6zLOfQFr2E2eSjRftTGw64hNUXWFwnKhcLWXx21hZTndAzKZVU/1fz6v5/Qfopl7By7l3tGnC+7JGUzJl3RVxjwgqofEISLuyFRqr2cvujuLuWuxfZBNQ8vHc+G8dDYFuZwh+qlNVa8yo5wNk3QKBgQDpjSpQxYAy6bTXon7l52lwX22iOJcG4o6jxVV5f0B6pmr8dYft7yJQP6Rf4y8nlkUj5vk2RDViT1clHHH3LYCddRhtcNQ8VzPBJB8Xa1Hjlg4egMJZaoBmcI3hXvUiUT1DqMtCpwbeq76mn7ShBSvDcYmjV5VDymk6uRbYBpZ/3QKBgQCGlkOSZJJXCbrnqo/SnIbBCWcF7ou6cZzynf1h3UV0R6PRH/GwM0ZNm9LpuXdfM/Mug5hk3SqYJZOPi/xn+bzk4bJASD37XNWd630XnIfRiQeQJCh1L6g1Zba67f2dLXqJjZUQafvT0E9/ucJ/kLH7q3dELcF3dCak5TjW0mYs3QKBgFHPlkwW8vJitWt3y3XjWyb29qOFqTnLMOYjYO6facnM89sdnJD3XJC5ym2gWktGs0+BQDkHKaAXZNJmJXHNaak+dGEZze6ZKVL1wUJl4JiVXrrGpc3GpdW8haa1qa7swEYsIY9mjNyBUtZxSUfCVPMwmWMzceD+TWA5p8vieuOtAoGAO5AW9XEWL22nm7Juro0RfFa7T3S8vvef4cFtrkT6mxbInAFfk8Ld++vozlU2vQuniYzRb9/mwdPsVE4dhXIMWzuLcg1aPV85gsIdE2VAqX1eAkZ1Sk/Jx0vsO/ooWaGzBM75+O1DLwq5LqtgoVAF5ZZaew7SUGXYI/7U55Kg1xs="),
				cipher:  []byte("!@#ASDiqzLFa6rOPRj4LJRqT7ZStD0hBiWrBB8nzo7IegiB8dceT7phmu1+xfHeRWD0rSKfXfc2O1oGBOjZOA593fsn7+q+xud5l08PJQOyuto/Qq8cg7kHyuq4aivNAu/P9gjsvPlghkeDRMAF7IMtBnBBHuR9wVvsWucVN/iuZTggLZ6gPhxw5fufuf29LslCLkIC+PSXZD71KdQAWDxrls/MHJwdEF1H6KVZeNbBQJwaKuESYibDg6ohlo9oejX1OW5bahfoX7RkOQW64q3JvYY/WPnyH4AAETkwoWaUxgH4/vBvl7qMlEZqQKcXZWPmcS3M14uzQ8+Lgp2ClkEfDR5wQ=="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros "),
			},
			wantErr: true,
		},
		{
			name:       "error cipher decryption",
			rsaFactory: RsaOAEPWithSHA256,
			args: args{
				pubKey:  []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxvDmplJ5hbjlBdPr+3iWtG3X/3/ZPiOYns4AECCf3xInnhAfnGrh9CJCiTtQAydjT95UEIP9SHUuYz1R9LQfgXv6wTfpwyaJ9otB71xJ6gGD0y24LD0sVj4T+QmpF3w/xI6fIZNYNKVjMb/vkSN9snnpTEHlFuI/upiVV765t7CkCgAafqbLTjJejsH0YtPPzPfVTQwVUu1wnv1behZuQ9gTu/ueZYdi9SbkZT8z2GPVvCZjx/WGx4ivumM9b3tstCEyOnTRKWYR4sZSR3wkW+HzocXRTzTvBNZ7RnhSGfp1XBbtLPI+h+PXNSUxCQMUKCwKjeJvnpdENgE8ZHW1yQIDAQAB"),
				privKey: []byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDG8OamUnmFuOUF0+v7eJa0bdf/f9k+I5iezgAQIJ/fEieeEB+cauH0IkKJO1ADJ2NP3lQQg/1IdS5jPVH0tB+Be/rBN+nDJon2i0HvXEnqAYPTLbgsPSxWPhP5CakXfD/Ejp8hk1g0pWMxv++RI32yeelMQeUW4j+6mJVXvrm3sKQKABp+pstOMl6OwfRi08/M99VNDBVS7XCe/Vt6Fm5D2BO7+55lh2L1JuRlPzPYY9W8JmPH9YbHiK+6Yz1ve2y0ITI6dNEpZhHixlJHfCRb4fOhxdFPNO8E1ntGeFIZ+nVcFu0s8j6H49c1JTEJAxQoLAqN4m+el0Q2ATxkdbXJAgMBAAECggEAEmU8Lqz5p6/NHZjW/U3NQanWiz2bLO/FsQmDX/pkThAzsZ30DlajxhtU47OkVmZR/JSmWVCbHxQW0f5dka8GKsb4DN3Ks8zgfPerhSKXgxfYxLI5kX2ml+Ltnd2S0SUgEGDPvh8NzPBuF6+Ty2vot5QmSnLdaBxLoElzpcVxDtcQ0X0Z7IdYyyUqvIGlHBWKvlgPRTNRwLLaLULNFWy40MyvlGiEm5uGZZ3mlM2V22MD1JEF7nhoewSH4MLvpoB/aiZuWGQCgTqGQTy9T9z7VQIl2t3N6xqAxnulBAO+D14nwzocDC3AMVoVv8TPcYKVJFJ0L1Y+XNxoQhzptLfmwQKBgQDaEBoUV5jv0TqIX3zyhyHDIQs6zLOfQFr2E2eSjRftTGw64hNUXWFwnKhcLWXx21hZTndAzKZVU/1fz6v5/Qfopl7By7l3tGnC+7JGUzJl3RVxjwgqofEISLuyFRqr2cvujuLuWuxfZBNQ8vHc+G8dDYFuZwh+qlNVa8yo5wNk3QKBgQDpjSpQxYAy6bTXon7l52lwX22iOJcG4o6jxVV5f0B6pmr8dYft7yJQP6Rf4y8nlkUj5vk2RDViT1clHHH3LYCddRhtcNQ8VzPBJB8Xa1Hjlg4egMJZaoBmcI3hXvUiUT1DqMtCpwbeq76mn7ShBSvDcYmjV5VDymk6uRbYBpZ/3QKBgQCGlkOSZJJXCbrnqo/SnIbBCWcF7ou6cZzynf1h3UV0R6PRH/GwM0ZNm9LpuXdfM/Mug5hk3SqYJZOPi/xn+bzk4bJASD37XNWd630XnIfRiQeQJCh1L6g1Zba67f2dLXqJjZUQafvT0E9/ucJ/kLH7q3dELcF3dCak5TjW0mYs3QKBgFHPlkwW8vJitWt3y3XjWyb29qOFqTnLMOYjYO6facnM89sdnJD3XJC5ym2gWktGs0+BQDkHKaAXZNJmJXHNaak+dGEZze6ZKVL1wUJl4JiVXrrGpc3GpdW8haa1qa7swEYsIY9mjNyBUtZxSUfCVPMwmWMzceD+TWA5p8vieuOtAoGAO5AW9XEWL22nm7Juro0RfFa7T3S8vvef4cFtrkT6mxbInAFfk8Ld++vozlU2vQuniYzRb9/mwdPsVE4dhXIMWzuLcg1aPV85gsIdE2VAqX1eAkZ1Sk/Jx0vsO/ooWaGzBM75+O1DLwq5LqtgoVAF5ZZaew7SUGXYI/7U55Kg1xs="),
				cipher:  []byte("aqzLFa6rOPRj4LJRqT7ZStD0hBiWrBB8nzo7IegiB8dceT7phmu1+xfHeRWD0rSKfXfc2O1oGBOjZOA593fsn7+q+xud5l08PJQOyuto/Qq8cg7kHyuq4aivNAu/P9gjsvPlghkeDRMAF7IMtBnBBHuR9wVvsWucVN/iuZTggLZ6gPhxw5fufuf29LslCLkIC+PSXZD71KdQAWDxrls/MHJwdEF1H6KVZeNbBQJwaKuESYibDg6ohlo9oejX1OW5bahfoX7RkOQW64q3JvYY/WPnyH4AAETkwoWaUxgH4/vBvl7qMlEZqQKcXZWPmcS3M14uzQ8+Lgp2ClkEfDR5wQ=="),
				plain:   []byte("Lorem ipsum dolor sit amet, consectetur adipiscing elit. Ut gravida vitae metus a lobortis. Ut nulla diam, tristique vel diam non, porta congue purus. Nunc at ornare orci. Ut pharetra, eros "),
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyPair, err := RsaLoadEncodedKeyPair(tt.args.privKey, tt.args.pubKey)
			assert.NoError(t, err)
			rsaInstance, err := tt.rsaFactory(keyPair)
			assert.NoError(t, err)

			got, err := rsaInstance.DecryptWithPrivateKey(tt.args.cipher)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptWithPrivateKey() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotEmpty(t, got)
			assert.Equal(t, tt.args.plain, got)
		})
	}
}

func TestRsaLoadEncodedKeyPair(t *testing.T) {
	var (
		pub2048  = []byte("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsb0ZWpIwQlxfUKuqLApIuVhcEuimDi2htczc41IbtSKJgzEyxr2qgwdwYOjf7kIUqgBx4hugLVtW0tudh504bdXWYVK0gKkhPW6N+eyk8XvB8fmdYirP9sepVj87w3n1/UN3+5st446o0hDbMoMlN/1/rA/pfbyz714LafhSKVRvUpBzF3FzFtQ0n69KdpWm2Ou72ibbALtHzp31+EtcNhcEhsW9XQmcz2gsQdKxbjgsKDDXtK+IEcCWDqV2CCE7wAPJgdX1oFQtkA0uyq/hoPDpSrQFL7mcJGKSWazUhUj3uWtdCXNhO/E+596vPzwZJMMKJJlQkSah3yqcr6C20QIDAQAB")
		priv2048 = []byte("MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCxvRlakjBCXF9Qq6osCki5WFwS6KYOLaG1zNzjUhu1IomDMTLGvaqDB3Bg6N/uQhSqAHHiG6AtW1bS252HnTht1dZhUrSAqSE9bo357KTxe8Hx+Z1iKs/2x6lWPzvDefX9Q3f7my3jjqjSENsygyU3/X+sD+l9vLPvXgtp+FIpVG9SkHMXcXMW1DSfr0p2labY67vaJtsAu0fOnfX4S1w2FwSGxb1dCZzPaCxB0rFuOCwoMNe0r4gRwJYOpXYIITvAA8mB1fWgVC2QDS7Kr+Gg8OlKtAUvuZwkYpJZrNSFSPe5a10Jc2E78T7n3q8/PBkkwwokmVCRJqHfKpyvoLbRAgMBAAECggEARItCjdU220C4WWn6dIV6yk+zIm+qKmmapXvd66Ssnsw07+03QcG/Uky6IAVu5nmBcpY9VQ+GVDeXYjXjqHsPWfxPcrTse3m+IezSwAFtEtvBTcoP0d3k2aziNyqnp5kPLp6oVNXhepJ3tJtfjTlaTx9p7zcrupvdYICKMlHbjagnEpvYLvsAczAOi+VE27AY1RsQwR0gpZYJdJoF/vvULuSWRUjf1D6X6mwjzb0hsEoX61YfAzPM5JPSeeBl4Q7KBUSaSq3Xnd9KoZRRP7vf6bl9gmzzw8mPvD+ZZlwI0oOJuDOW8DPhgADqxxcprKyM8A1HO/WQ6odQFftI5VjcgQKBgQDqBmUzdm4SASXRyPKKou4EEaE/FuqKmpBkVrCfYvdG2yXNwJ+L/NQ9Ok6+3g4Qqo7DvbeOoaX8JJhK2W662Kn9DlAD7OVM7Rf6s3huzHZ0G85XmdcKrTXF4r1w2M7X0RsZ3WNIymS0wXxraQdChpw99mzRNZroSUM/23a+dsbc+QKBgQDCbaqVBzkRkfqema6AFeODXc8JZER1zu9RzqLx5BfdamlaKn7e+a25b745PzaVusVNDZxeZIGyFq3S27m4wo1bDgLxxY7PWvETt2C4F4kQw0rj5gkjleNwa+jwGDhdwRRwxeBXduFHVNpz1lYXDUe86NRbE3M0uSshYOAaQqNWmQKBgAsF+BhfeLnSYgSqsXoESK/aYL0HCE81Dp4bU0B+ueUVh4dUjm9anmiv6WumLAVu80CXHCFUzeu9kYrdCRE2CXPJC83Th82C0YFWmNKnQOEhOiv4LB/tnr3Oe1voan3R9LPYMMgJ+IpnHsQ0c0oX6x4kEGYeX0iXwtosLUC1eZKJAoGANbM+exzcmUq9ctK1jLD+/siJJ2nnMrauCOVOwgqiwMfkQ0AbfJBveBkx6/PWqrJETkzlFHkkDUEQT33apPovOqf7DjXnhMP0c+KhNxdhBx05cQqXGZoLkIBtfOrjnpl2gNNWbDHsdNwt3fKkIofLeZTBGkqb9kLyc6yjGP2wyXkCgYEAn/AOl8m/BWDy6ov3qfUFtp6Q8XGczHvob3zRxwFzTQ6f6pUxpXR9w72VHyQBFls7OQchNAgeIRcHNHNMVPQe5qDD1nrMr8H3RkaGm3or+SEtt1JDewpps9v8V+kc6kz7eicIixYMyObHfPYIzfzhxVEsLNioDi0Zm+c61jwu6aA=")
		pub4096  = []byte("MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA10vtoa5ZHF1Pl/VFMl8F8AZp2WJ9gGRGgLlyiLzUm2v2fqB/mkJVEP79uZQfyzfILmONy6knBgOdg1sMcH1HZDhfSUGe4AI0TqnCuvCEkXON5qup76hyr90lSpgPU9FnuYtxjpMbvkKd6QBc5szeLUQlzyBEs7BuM1PHBaOMmMyN9tp7NqNkLDzqsWSLn4rSVHyd1wPYaptN4nj6e1aKGGyVtSFIdvPbuqcmNS+41+QM0u6lZ9aCHhNGoS/q7RbFNRdKO0gLcwxcxRdJsoWmjIrfYHD4aSPzjRzlD/Otq8SpHp+n5677qOxi8o5MEhVeUkHkNGohBf9qyI4JYMFYsOD4oX1DYRnP095H1stDkfYMzx61gyjLcsf3dQi2D9oloemtTuSARndtZI/9N0u+1RvOhGtLwLN+Sn/UQ8mKKZlBRWDiFg0xhcvp0vys76jvCDJoF2Vi05FFZd8QNmfX/4X7cK80VoxHBfnvrjnB/yf4LEQGhrOY0COsQNu0VZMcIBuJ7RYPZ/cSTafTaTVE1Smjfe9mtBA4B+UqewKJBA9SstVbMm7Le/h0QUKG0hirkAjM0o9uLIz3LPk25MUZ5ZyoB0ps5nZCvsprffGZy8V+XVqpfl+g5hTlZDtaNVdcdBASJjXN8tpz166v81t73sL1HrIM54CbND5FPl4hAsECAwEAAQ==")
		priv4096 = []byte("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")
	)

	edPub, edPriv, err := ed25519.GenerateKey(getRandomReader())
	assert.NoError(t, err)

	pub, err := x509.MarshalPKIXPublicKey(edPub)
	assert.NoError(t, err)
	priv, err := x509.MarshalPKCS8PrivateKey(edPriv)
	assert.NoError(t, err)

	encodedEdPub, err := base64Encode(getBase64Encoder(), pub)
	assert.NoError(t, err)
	encodedEdPriv, err := base64Encode(getBase64Encoder(), priv)
	assert.NoError(t, err)

	type args struct {
		privateKey []byte
		publicKey  []byte
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name: "success rsa key 2048",
			args: args{
				publicKey:  pub2048,
				privateKey: priv2048,
			},
			wantErr: false,
		},
		{
			name: "success rsa key 4096",
			args: args{
				publicKey:  pub4096,
				privateKey: priv4096,
			},
			wantErr: false,
		},
		{
			name: "error empty",
			args: args{
				publicKey:  []byte{},
				privateKey: []byte{},
			},
			wantErr: true,
		},
		{
			name: "error nil",
			args: args{
				publicKey:  pub2048,
				privateKey: nil,
			},
			wantErr: true,
		},
		{
			name: "error decode base64",
			args: args{
				publicKey:  pub2048,
				privateKey: append(priv2048, []byte("!@#")...),
			},
			wantErr: true,
		},
		{
			name: "error decode base64 2",
			args: args{
				publicKey:  append(pub2048, []byte("!@#")...),
				privateKey: priv2048,
			},
			wantErr: true,
		},
		{
			name: "error invalid rsa pub",
			args: args{
				publicKey:  encodedEdPub,
				privateKey: priv2048,
			},
			wantErr: true,
		},
		{
			name: "error invalid rsa priv",
			args: args{
				publicKey:  pub2048,
				privateKey: encodedEdPriv,
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := RsaLoadEncodedKeyPair(tt.args.privateKey, tt.args.publicKey)
			if (err != nil) != tt.wantErr {
				t.Errorf("RsaLoadEncodedKeyPair() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.NotNil(t, got)
			assert.NotEmpty(t, got.Private())
			assert.NotEmpty(t, got.Public())
			assert.NotEmpty(t, got.PrivateRsa())
			assert.NotEmpty(t, got.PublicRsa())

			encodedPubKey, err := got.EncodedPublic()
			assert.NoError(t, err)
			assert.Equal(t, tt.args.publicKey, encodedPubKey)

			encodedPrivKey, err := got.EncodedPrivate()
			assert.NoError(t, err)
			assert.Equal(t, tt.args.privateKey, encodedPrivKey)
		})
	}
}

package ezcrypt

import (
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"testing"
)

func Test_base64Encode(t *testing.T) {
	type args struct {
		encoder *base64.Encoding
		val     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				encoder: base64.StdEncoding,
				val:     []byte("test"),
			},
			want:    []byte{100, 71, 86, 122, 100, 65, 61, 61},
			wantErr: false,
		},
		{
			name: "success 2",
			args: args{
				encoder: base64.StdEncoding,
				val:     nil,
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "error",
			args: args{
				encoder: nil,
				val:     []byte("test"),
			},
			want:    []byte{100, 71, 86, 122, 100, 65, 61, 61},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64Encode(tt.args.encoder, tt.args.val)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64Encode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("base64Encode() invalid length, got %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("base64Encode() is not equal, got %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}

func Test_base64Decode(t *testing.T) {
	type args struct {
		encoder *base64.Encoding
		val     []byte
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		wantErr bool
	}{
		{
			name: "success",
			args: args{
				encoder: base64.StdEncoding,
				val:     nil,
			},
			want:    []byte{},
			wantErr: false,
		},
		{
			name: "success 2",
			args: args{
				encoder: base64.StdEncoding,
				val:     []byte{100, 71, 86, 122, 100, 65, 61, 61},
			},
			want:    []byte("test"),
			wantErr: false,
		},
		{
			name: "error",
			args: args{
				encoder: nil,
				val:     []byte{100, 71, 86, 122, 100, 65, 61, 61},
			},
			want:    []byte("test"),
			wantErr: true,
		},
		{
			name: "error 2",
			args: args{
				encoder: base64.StdEncoding,
				val:     []byte{100, 71, 86, 122, 100, 65, 61, 61, 63},
			},
			want:    []byte("test"),
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := base64Decode(tt.args.encoder, tt.args.val)
			if (err != nil) != tt.wantErr {
				t.Errorf("base64Decode() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if len(got) != len(tt.want) {
				t.Errorf("base64Decode() invalid length, got %v, want %v", len(got), len(tt.want))
				return
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("base64Decode() is not equal, got %v, want %v", got, tt.want)
					return
				}
			}
		})
	}
}

func TestGenerateRandomBytes(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{n: 32},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateRandomBytes(tt.args.n)
			assert.Len(t, got, tt.args.n)
		})
	}
}

func TestGenerateRandomString(t *testing.T) {
	type args struct {
		n int
	}
	tests := []struct {
		name string
		args args
	}{
		{
			name: "success",
			args: args{n: 32},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateRandomString(tt.args.n)
			assert.Len(t, got, tt.args.n)
		})
	}
}

func BenchmarkGenerateRandomBytes(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateRandomBytes(32)
	}
}

func BenchmarkGenerateRandomString(b *testing.B) {
	for i := 0; i < b.N; i++ {
		generateRandomString(32)
	}
}

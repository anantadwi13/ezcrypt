package ezcrypt

import (
	"crypto/rand"
	"encoding/base64"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

func TestSetRandomReader(t *testing.T) {
	type args struct {
		reader io.Reader
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			args:    args{reader: rand.Reader},
			wantErr: false,
		},
		{
			name:    "error nil",
			args:    args{reader: nil},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetRandomReader(tt.args.reader)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetRandomReader() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.Equal(t, tt.args.reader, getRandomReader())
		})
	}
}

func TestSetBase64Encoder(t *testing.T) {
	type args struct {
		encoder *base64.Encoding
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			name:    "success",
			args:    args{encoder: base64.StdEncoding},
			wantErr: false,
		},
		{
			name:    "error nil",
			args:    args{encoder: nil},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SetBase64Encoder(tt.args.encoder)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetBase64Encoder() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			assert.Equal(t, tt.args.encoder, getBase64Encoder())
		})
	}
}

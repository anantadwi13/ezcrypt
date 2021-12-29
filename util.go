package ezcrypt

import (
	"encoding/base64"
	"errors"
)

func base64Encode(encoder *base64.Encoding, val []byte) ([]byte, error) {
	if encoder == nil {
		return nil, errors.New("encoder is nil")
	}
	encodedBytes := make([]byte, encoder.EncodedLen(len(val)))
	encoder.Encode(encodedBytes, val)
	return encodedBytes, nil
}

func base64Decode(encoder *base64.Encoding, val []byte) ([]byte, error) {
	if encoder == nil {
		return nil, errors.New("encoder is nil")
	}
	decodedBytes := make([]byte, encoder.DecodedLen(len(val)))
	n, err := encoder.Decode(decodedBytes, val)
	if err != nil {
		return nil, err
	}
	return decodedBytes[:n], nil
}

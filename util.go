package ezcrypt

import (
	"encoding/base64"
	"errors"
	mathrand "math/rand"
	"strings"
	"time"
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

const (
	letterBytes   = "abcdefghijklmnopqrstuvwxyz!@#$%^&*()-=ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	letterIdxBits = 7                    // 6 bits to represent a letter index
	letterIdxMask = 1<<letterIdxBits - 1 // All 1-bits, as many as letterIdxBits
	letterIdxMax  = 63 / letterIdxBits   // # of letter indices fitting in 63 bits
)

var (
	src     = mathrand.NewSource(time.Now().UnixNano())
	randNew = mathrand.New(src)
)

func generateRandomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	// A src.Int63() generates 63 random bits, enough for letterIdxMax characters!
	for i, cache, remain := n-1, randNew.Int63(), letterIdxMax; i >= 0; {
		if remain == 0 {
			cache, remain = randNew.Int63(), letterIdxMax
		}
		if idx := int(cache & letterIdxMask); idx < len(letterBytes) {
			sb.WriteByte(letterBytes[idx])
			i--
		}
		cache >>= letterIdxBits
		remain--
	}

	return sb.String()
}

func generateRandomBytes(n int) []byte {
	buf := make([]byte, n)
	// no need to check n & err
	_, _ = randNew.Read(buf)
	return buf
}

package util

import (
	"crypto/rand"
	"encoding/hex"
)

func NewID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

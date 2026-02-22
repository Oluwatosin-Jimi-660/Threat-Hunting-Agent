package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func ValidateSignedRulePackage(pkg SignedRulePackage, publicKeyBase64 string) error {
	if publicKeyBase64 == "" {
		return errors.New("missing rule signing key")
	}
	pubRaw, err := base64.StdEncoding.DecodeString(publicKeyBase64)
	if err != nil {
		return err
	}
	sigRaw, err := base64.StdEncoding.DecodeString(pkg.Signature)
	if err != nil {
		return err
	}
	payload, err := json.Marshal(pkg.Payload)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(pubRaw), payload, sigRaw) {
		return errors.New("invalid rule package signature")
	}
	return validateRuleSet(pkg.Payload)
}

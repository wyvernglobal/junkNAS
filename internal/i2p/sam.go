// Package i2p — b32.go
//
// Derives this node's .b32.i2p address by reading the keyfile that i2pd
// writes for the server tunnel. No network calls needed — pure file parsing.
//
// i2pd keyfile binary layout:
//
//	[0:256]   ElGamal public key (256 bytes)
//	[256:384] Signing public key (128 bytes, padded for older key types)
//	[384:]    Certificate: type(1) + length(2) + data(length)
//
// The I2P "destination" is pubkey || sigkey || certificate.
// B32 address = base32_lower(SHA-256(destination)), no padding.
package i2p

import (
	"crypto/sha256"
	"encoding/base32"
	"fmt"
	"os"
	"strings"
)

// b32FromKeyFile derives the .b32.i2p address from an i2pd keyfile.
func b32FromKeyFile(keyFile string) (string, error) {
	data, err := os.ReadFile(keyFile)
	if err != nil {
		return "", fmt.Errorf("b32: read keyfile %s: %w", keyFile, err)
	}
	if len(data) < 387 {
		return "", fmt.Errorf("b32: keyfile too short (%d bytes)", len(data))
	}

	const baseLen = 384 // 256 (ElGamal) + 128 (signing key, padded)
	if len(data) < baseLen+3 {
		return "", fmt.Errorf("b32: keyfile too short for certificate header")
	}

	certLen := int(data[baseLen+1])<<8 | int(data[baseLen+2])
	destEnd := baseLen + 3 + certLen
	if len(data) < destEnd {
		return "", fmt.Errorf("b32: keyfile truncated (need %d, have %d)", destEnd, len(data))
	}

	hash := sha256.Sum256(data[:destEnd])
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	return strings.ToLower(enc.EncodeToString(hash[:])) + b32Suffix + ":36789", nil
}

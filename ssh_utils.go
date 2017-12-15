package main

import (
	"crypto/sha256"
	"encoding/base64"

	"golang.org/x/crypto/ssh/agent"
)

// FingerprintSHA256 returns the user presentation of the key's
// fingerprint as unpadded base64 encoded sha256 hash.
// This format was introduced from OpenSSH 6.8.
// https://www.openssh.com/txt/release-6.8
// https://tools.ietf.org/html/rfc4648#section-3.2 (unpadded base64 encoding)
func fingerprintSHA256(pubKey *agent.Key) string {
	sha256sum := sha256.Sum256(pubKey.Blob)
	hash := base64.RawStdEncoding.EncodeToString(sha256sum[:])
	return "SHA256:" + hash + " " + pubKey.Comment + " (" + pubKey.Format + ")"
}

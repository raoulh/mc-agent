package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
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
	return "SHA256:" + hash
}

func getPubKey(addedKey *agent.AddedKey) (*agent.Key, error) {
	return getPubKeyRaw(addedKey.PrivateKey, addedKey.Comment)
}

func getPubKeyRaw(key interface{}, comment string) (*agent.Key, error) {
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		return nil, err
	}

	pub := signer.PublicKey()
	pubKey := &agent.Key{
		Format:  pub.Type(),
		Blob:    pub.Marshal(),
		Comment: comment,
	}

	return pubKey, nil
}

func parseKeyBlob(blob []byte) (addedKey *agent.AddedKey, err error) {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	if err = ssh.Unmarshal(blob, &record); err != nil {
		return nil, err
	}

	switch record.Type {
	case ssh.KeyAlgoRSA:
		addedKey, err = parseRSAKey(blob)
	case ssh.KeyAlgoDSA:
		addedKey, err = parseDSAKey(blob)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		addedKey, err = parseECDSAKey(blob)
	case ssh.KeyAlgoED25519:
		addedKey, err = parseEd25519Key(blob)
	case ssh.CertAlgoRSAv01:
		addedKey, err = parseRSACert(blob)
	case ssh.CertAlgoDSAv01:
		addedKey, err = parseDSACert(blob)
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		addedKey, err = parseECDSACert(blob)
	case ssh.CertAlgoED25519v01:
		addedKey, err = parseEd25519Cert(blob)
	default:
		return nil, fmt.Errorf("agent: not implemented: %q", record.Type)
	}

	return
}

func (mk McKey) ToBlob() (blob []byte) {
	switch k := mk.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if len(k.Primes) != 2 {
			log.Printf("agent: unsupported RSA key with %d primes\n", len(k.Primes))
			return
		}
		k.Precompute()
		blob = ssh.Marshal(rsaKeyMsg{
			Type:     ssh.KeyAlgoRSA,
			N:        k.N,
			E:        big.NewInt(int64(k.E)),
			D:        k.D,
			Iqmp:     k.Precomputed.Qinv,
			P:        k.Primes[0],
			Q:        k.Primes[1],
			Comments: mk.Comment,
		})
	case *dsa.PrivateKey:
		blob = ssh.Marshal(dsaKeyMsg{
			Type:     ssh.KeyAlgoDSA,
			P:        k.P,
			Q:        k.Q,
			G:        k.G,
			Y:        k.Y,
			X:        k.X,
			Comments: mk.Comment,
		})
	case *ecdsa.PrivateKey:
		nistID := fmt.Sprintf("nistp%d", k.Params().BitSize)
		blob = ssh.Marshal(ecdsaKeyMsg{
			Type:     "ecdsa-sha2-" + nistID,
			Curve:    nistID,
			KeyBytes: elliptic.Marshal(k.Curve, k.X, k.Y),
			D:        k.D,
			Comments: mk.Comment,
		})
	case *ed25519.PrivateKey:
		blob = ssh.Marshal(ed25519KeyMsg{
			Type:     ssh.KeyAlgoED25519,
			Pub:      []byte(*k)[32:],
			Priv:     []byte(*k),
			Comments: mk.Comment,
		})
	}

	return blob
}

func ToMcKey(addedKey *agent.AddedKey) *McKey {
	mk := AddedKeyToMcKey(addedKey)
	return &mk
}

func AddedKeyToMcKey(addedKey *agent.AddedKey) McKey {
	mck := McKey{
		PrivateKey: addedKey.PrivateKey,
		Comment:    addedKey.Comment,
	}

	return mck
}

func readOpensshComment(data []byte) string {
	magic := append([]byte("openssh-key-v1"), 0)
	remaining := data[len(magic):]

	var w struct {
		CipherName   string
		KdfName      string
		KdfOpts      string
		NumKeys      uint32
		PubKey       []byte
		PrivKeyBlock []byte
	}

	if err := ssh.Unmarshal(remaining, &w); err != nil {
		return ""
	}

	pk1 := struct {
		Check1  uint32
		Check2  uint32
		Keytype string
		Rest    []byte `ssh:"rest"`
	}{}

	if err := ssh.Unmarshal(w.PrivKeyBlock, &pk1); err != nil {
		return ""
	}

	switch pk1.Keytype {
	case ssh.KeyAlgoRSA:
		// https://github.com/openssh/openssh-portable/blob/master/sshkey.c#L2760-L2773
		key := struct {
			N       *big.Int
			E       *big.Int
			D       *big.Int
			Iqmp    *big.Int
			P       *big.Int
			Q       *big.Int
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return ""
		}

		return key.Comment
	case ssh.KeyAlgoED25519:
		key := struct {
			Pub     []byte
			Priv    []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}{}

		if err := ssh.Unmarshal(pk1.Rest, &key); err != nil {
			return ""
		}

		return key.Comment
	default:
		return ""
	}

	return ""
}

func readPubComment(fname string) string {
	fileData, err := ioutil.ReadFile(fname)
	if err != nil {
		return ""
	}

	tokens := strings.Split(string(fileData), " ")

	if len(tokens) < 3 {
		return ""
	}

	return tokens[2]
}

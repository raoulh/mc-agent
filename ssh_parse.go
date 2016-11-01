package main

//Code from golang ssh server implementation

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

type rsaKeyMsg struct {
	Type        string `sshtype:"17|25"`
	N           *big.Int
	E           *big.Int
	D           *big.Int
	Iqmp        *big.Int // IQMP = Inverse Q Mod P
	P           *big.Int
	Q           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type dsaKeyMsg struct {
	Type        string `sshtype:"17|25"`
	P           *big.Int
	Q           *big.Int
	G           *big.Int
	Y           *big.Int
	X           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type ecdsaKeyMsg struct {
	Type        string `sshtype:"17|25"`
	Curve       string
	KeyBytes    []byte
	D           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type ed25519KeyMsg struct {
	Type        string `sshtype:"17|25"`
	Pub         []byte
	Priv        []byte
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type rsaCertMsg struct {
	Type        string `sshtype:"17|25"`
	CertBytes   []byte
	D           *big.Int
	Iqmp        *big.Int // IQMP = Inverse Q Mod P
	P           *big.Int
	Q           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type dsaCertMsg struct {
	Type        string `sshtype:"17|25"`
	CertBytes   []byte
	X           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type ecdsaCertMsg struct {
	Type        string `sshtype:"17|25"`
	CertBytes   []byte
	D           *big.Int
	Comments    string
	Constraints []byte `ssh:"rest"`
}

type ed25519CertMsg struct {
	Type        string `sshtype:"17|25"`
	CertBytes   []byte
	Pub         []byte
	Priv        []byte
	Comments    string
	Constraints []byte `ssh:"rest"`
}

func parseRSAKey(req []byte) (*agent.AddedKey, error) {
	var k rsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	if k.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}
	priv := &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(k.E.Int64()),
			N: k.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.P, k.Q},
	}
	priv.Precompute()

	return &agent.AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func parseEd25519Key(req []byte) (*agent.AddedKey, error) {
	var k ed25519KeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)
	return &agent.AddedKey{PrivateKey: &priv, Comment: k.Comments}, nil
}

func parseDSAKey(req []byte) (*agent.AddedKey, error) {
	var k dsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: k.P,
				Q: k.Q,
				G: k.G,
			},
			Y: k.Y,
		},
		X: k.X,
	}

	return &agent.AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func unmarshalECDSA(curveName string, keyBytes []byte, privScalar *big.Int) (priv *ecdsa.PrivateKey, err error) {
	priv = &ecdsa.PrivateKey{
		D: privScalar,
	}

	switch curveName {
	case "nistp256":
		priv.Curve = elliptic.P256()
	case "nistp384":
		priv.Curve = elliptic.P384()
	case "nistp521":
		priv.Curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("agent: unknown curve %q", curveName)
	}

	priv.X, priv.Y = elliptic.Unmarshal(priv.Curve, keyBytes)
	if priv.X == nil || priv.Y == nil {
		return nil, errors.New("agent: point not on curve")
	}

	return priv, nil
}

func parseEd25519Cert(req []byte) (*agent.AddedKey, error) {
	var k ed25519CertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	priv := ed25519.PrivateKey(k.Priv)
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ED25519 certificate")
	}
	return &agent.AddedKey{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseECDSAKey(req []byte) (*agent.AddedKey, error) {
	var k ecdsaKeyMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(k.Curve, k.KeyBytes, k.D)
	if err != nil {
		return nil, err
	}

	return &agent.AddedKey{PrivateKey: priv, Comment: k.Comments}, nil
}

func parseRSACert(req []byte) (*agent.AddedKey, error) {
	var k rsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}

	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad RSA certificate")
	}

	// An RSA publickey as marshaled by rsaPublicKey.Marshal() in keys.go
	var rsaPub struct {
		Name string
		E    *big.Int
		N    *big.Int
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &rsaPub); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	if rsaPub.E.BitLen() > 30 {
		return nil, errors.New("agent: RSA public exponent too large")
	}

	priv := rsa.PrivateKey{
		PublicKey: rsa.PublicKey{
			E: int(rsaPub.E.Int64()),
			N: rsaPub.N,
		},
		D:      k.D,
		Primes: []*big.Int{k.Q, k.P},
	}
	priv.Precompute()

	return &agent.AddedKey{PrivateKey: &priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseDSACert(req []byte) (*agent.AddedKey, error) {
	var k dsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}
	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad DSA certificate")
	}

	// A DSA publickey as marshaled by dsaPublicKey.Marshal() in keys.go
	var w struct {
		Name       string
		P, Q, G, Y *big.Int
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &w); err != nil {
		return nil, fmt.Errorf("agent: Unmarshal failed to parse public key: %v", err)
	}

	priv := &dsa.PrivateKey{
		PublicKey: dsa.PublicKey{
			Parameters: dsa.Parameters{
				P: w.P,
				Q: w.Q,
				G: w.G,
			},
			Y: w.Y,
		},
		X: k.X,
	}

	return &agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: k.Comments}, nil
}

func parseECDSACert(req []byte) (*agent.AddedKey, error) {
	var k ecdsaCertMsg
	if err := ssh.Unmarshal(req, &k); err != nil {
		return nil, err
	}

	pubKey, err := ssh.ParsePublicKey(k.CertBytes)
	if err != nil {
		return nil, err
	}
	cert, ok := pubKey.(*ssh.Certificate)
	if !ok {
		return nil, errors.New("agent: bad ECDSA certificate")
	}

	// An ECDSA publickey as marshaled by ecdsaPublicKey.Marshal() in keys.go
	var ecdsaPub struct {
		Name string
		ID   string
		Key  []byte
	}
	if err := ssh.Unmarshal(cert.Key.Marshal(), &ecdsaPub); err != nil {
		return nil, err
	}

	priv, err := unmarshalECDSA(ecdsaPub.ID, ecdsaPub.Key, k.D)
	if err != nil {
		return nil, err
	}

	return &agent.AddedKey{PrivateKey: priv, Certificate: cert, Comment: k.Comments}, nil
}

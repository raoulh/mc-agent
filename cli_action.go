package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"reflect"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	//https://github.com/openssh/openssh-portable/blob/315d2a4e674d0b7115574645cb51f968420ebb34/cipher.c#L98
	CipherNoneBlockSize = 8
)

func doCliAction(action string) {
	log.Println("CLI Action:", action)
	var err error

	var jarray []JsonKey
	if action == "list" {
		jarray, err = doList()
	}

	if err != nil {
		log.Println("Error:", err)
		return
	}

	jsonData, _ := json.Marshal(jarray)
	fmt.Println(string(jsonData))
}

type JsonKey struct {
	PublicKey   string
	PrivateKey  string
	Fingerprint string
}

func doList() (jarray []JsonKey, err error) {
	a := NewSshAgent()

	k, err := McLoadKeys()
	if err == nil {
		if err = a.addKeysToKeychain(k); err != nil {
			return jarray, fmt.Errorf("Failed to load keys from Moolticute: %v", err)
		} else {
			if len(*k) > 0 { //only set keys loaded if keys are present
				a.keysLoaded = true
			}
			log.Println(len(*k), "keys loaded from MP")
		}
	}

	keys, err := a.keyring.List()
	if err != nil {
		return jarray, err
	}

	for i, k := range keys {
		a.Keys[i].pubKey = k
	}

	for _, mck := range a.Keys {
		jkey := JsonKey{
			PublicKey:   mck.pubKey.String(),
			Fingerprint: fingerprintSHA256(mck.pubKey) + " " + mck.pubKey.Comment + " (" + mck.pubKey.Format + ")",
		}

		//Read the key blob and recreate a usable key format for the user
		var record struct {
			Type string `sshtype:"17|25"`
			Rest []byte `ssh:"rest"`
		}

		if err := ssh.Unmarshal(mck.keyBlob, &record); err != nil {
			return jarray, err
		}

		var addedKey *agent.AddedKey
		var priv interface{}

		switch record.Type {
		case ssh.KeyAlgoRSA:
			addedKey, err = parseRSAKey(mck.keyBlob)
			priv = addedKey.PrivateKey
		case ssh.KeyAlgoDSA:
			addedKey, err = parseDSAKey(mck.keyBlob)
			priv = addedKey.PrivateKey
		case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
			addedKey, err = parseECDSAKey(mck.keyBlob)
			priv = addedKey.PrivateKey
		case ssh.KeyAlgoED25519:
			addedKey, err = parseEd25519Key(mck.keyBlob)
			priv = addedKey.PrivateKey
		case ssh.CertAlgoRSAv01:
			addedKey, err = parseRSACert(mck.keyBlob)
		case ssh.CertAlgoDSAv01:
			addedKey, err = parseDSACert(mck.keyBlob)
		case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
			addedKey, err = parseECDSACert(mck.keyBlob)
		case ssh.CertAlgoED25519v01:
			addedKey, err = parseEd25519Cert(mck.keyBlob)
		default:
			return jarray, fmt.Errorf("key type not implemented: %q", record.Type)
		}
		if err != nil {
			return jarray, err
		}

		pemblock := pemBlockForKey(priv, mck.pubKey)
		if pemblock != nil {
			jkey.PrivateKey = string(pem.EncodeToMemory(pemblock))
		} else {
			log.Println("Error, nil key!!")
			continue
		}

		jarray = append(jarray, jkey)
	}

	return
}

type DSAKeyFormat struct {
	Version       int
	P, Q, G, Y, X *big.Int
}

func pemBlockForKey(priv interface{}, agentPubKey *agent.Key) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *dsa.PrivateKey:
		val := DSAKeyFormat{
			P: k.P, Q: k.Q, G: k.G,
			Y: k.Y, X: k.X,
		}
		bytes, _ := asn1.Marshal(val)
		return &pem.Block{Type: "DSA PRIVATE KEY", Bytes: bytes}
	case *ecdsa.PrivateKey:
		b, _ := x509.MarshalECPrivateKey(k)
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	case *ed25519.PrivateKey:

		pub := k.Public().(ed25519.PublicKey)

		//ED25519 key
		edkey := struct {
			Check1  uint32
			Check2  uint32
			Keytype string
			Pub     ed25519.PublicKey
			Priv    []byte
			Comment string
			Pad     []byte `ssh:"rest"`
		}{
			Check1:  324328077, //random int should match
			Check2:  324328077,
			Keytype: ssh.KeyAlgoED25519,
			Pub:     pub,
			Priv:    *k,
			Comment: agentPubKey.Comment,
		}

		//padding
		i := 1
		for (len(ssh.Marshal(edkey)) % CipherNoneBlockSize) != 0 {
			edkey.Pad = append(edkey.Pad, byte(i&0xff))
			i++
		}

		//openssh container
		w := struct {
			CipherName   string
			KdfName      string
			KdfOpts      string
			NumKeys      uint32
			PubKey       []byte
			PrivKeyBlock []byte
		}{
			CipherName:   "none",
			KdfName:      "none",
			NumKeys:      1,
			PubKey:       []byte(pub),
			PrivKeyBlock: ssh.Marshal(edkey),
		}

		var b []byte
		magic := append([]byte("openssh-key-v1"), 0)
		b = append(b, magic...)
		b = append(b, ssh.Marshal(w)...)

		return &pem.Block{Type: "OPENSSH PRIVATE KEY", Bytes: b}
	default:
		fmt.Println("Unknown key type:", reflect.TypeOf(priv))
		return nil
	}
}

type ListKeyAction int

const (
	ListPublicKeys ListKeyAction = iota
	ListPubFinger
	ListPrivKey
)

func listKeysCommand(action ListKeyAction, keyNum int) {
	jarray, err := doList()

	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	if keyNum >= len(jarray) {
		fmt.Println("Error:", keyNum, "is out of range. Only", len(jarray), "keys available.")
		return
	}

	switch action {
	case ListPublicKeys:
		if keyNum < 0 {
			for i, k := range jarray {
				fmt.Printf("[%d]: %s\n", i, k.PublicKey)
			}
		} else {
			fmt.Printf("%s\n", jarray[keyNum].PublicKey)
		}
	case ListPubFinger:
		fmt.Println("Print fingerprints")
		if keyNum < 0 {
			for i, k := range jarray {
				fmt.Printf("[%d]: %s\n", i, k.Fingerprint)
			}
		} else {
			fmt.Printf("%s\n", jarray[keyNum].Fingerprint)
		}
	case ListPrivKey:
		if keyNum < 0 {
			for i, k := range jarray {
				fmt.Printf("Private key %d:\n%s\n", i, k.PrivateKey)
			}
		} else {
			fmt.Printf("%s\n", jarray[keyNum].PrivateKey)
		}
	}
}

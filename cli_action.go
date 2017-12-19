package main

import (
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"math/big"
	"reflect"
	"strings"

	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	//https://github.com/openssh/openssh-portable/blob/315d2a4e674d0b7115574645cb51f968420ebb34/cipher.c#L98
	CipherNoneBlockSize = 8
)

type ErrorJson struct {
	Error        bool   `json:"error"`
	ErrorMessage string `json:"error_message,omitempty"`
}

func createJsonError(e bool, m string) string {
	j := ErrorJson{
		Error:        e,
		ErrorMessage: m,
	}

	js, _ := json.Marshal(j)
	return string(js)
}

func doCliAction(action string, keyNum int, filename string) {
	log.Println("CLI Action:", action)
	var err error
	var jsonData string

	var jarray []JsonKey
	if action == "list" {
		jarray, err = doList()

		if err != nil {
			log.Println("Error:", err)
			jsonData = createJsonError(true, fmt.Sprintf("Failed to list: %v", err))
		} else {
			j, _ := json.Marshal(jarray)
			jsonData = string(j)
		}
	}

	if action == "delete" {
		if err = delKeys(keyNum); err != nil {
			jsonData = createJsonError(true, fmt.Sprintf("Failed to delete key: %v", err))
		} else {
			jsonData = createJsonError(false, "")
		}
	}

	if action == "add" {
		if err := addKey(filename); err != nil {
			jsonData = createJsonError(true, fmt.Sprintf("Failed to add key: %v", err))
		} else {
			jsonData = createJsonError(false, "")
		}
	}

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

	if len(jarray) == 0 {
		fmt.Println("No keys.")
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

func delKeysCommand(keyNum int) {
	if err := delKeys(keyNum); err != nil {
		fmt.Println("Failed to delete key:", err)
	} else {
		fmt.Println("Key deleted successfully")
	}
}

func delKeys(keyNum int) (err error) {
	a := NewSshAgent()

	k, err := McLoadKeys()
	if err == nil {
		if err = a.addKeysToKeychain(k); err != nil {
			return fmt.Errorf("Failed to load keys from Moolticute: %v\n", err)
		} else {
			if len(*k) > 0 { //only set keys loaded if keys are present
				a.keysLoaded = true
			}
			log.Println(len(*k), "keys loaded from MP")
		}
	}

	if keyNum < 0 {
		if err := a.removeAllKeys(true); err != nil {
			return fmt.Errorf("Failed to remove all keys: %v", err)
		}
	} else {
		if keyNum >= len(*k) {
			return fmt.Errorf("Error:", keyNum, "is out of range. Only", len(*k), "keys available.")
		}

		//found the key, delete it
		copy(a.Keys[keyNum:], a.Keys[keyNum+1:])
		a.Keys[len(a.Keys)-1].addedKey = nil //do not leak
		a.Keys[len(a.Keys)-1].pubKey = nil   //do not leak
		a.Keys = a.Keys[:len(a.Keys)-1]

		//Send keys to moolticute
		if err := McSetKeys(a.ToMcKeys()); err != nil {
			return fmt.Errorf("Failed to remove key from moolticute: %v", err)
		}
	}

	return err
}

func addKeyCommand(filename string) {
	if err := addKey(filename); err != nil {
		fmt.Println("Failed to add key:", err)
	} else {
		fmt.Println("Key added successfully")
	}
}

func addKey(filename string) (err error) {
	fileData, err := ioutil.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("Failed to read file, %v", err)
	}

	key, err := ssh.ParseRawPrivateKey(fileData)
	if err != nil {
		return fmt.Errorf("Failed to parse file, %v", err)
	}

	//Reparse the file and try to read the comment. The Golang api does
	// not export the comment field
	var comment string

	block, _ := pem.Decode(fileData)
	if block == nil {
		return errors.New("ssh: no key found")
	}

	switch block.Type {
	case "OPENSSH PRIVATE KEY":
		//In openssh format the comment is included inside the data block
		comment = readOpensshComment(block.Bytes)
	}

	if comment == "" {
		//try reading the comment from the .pub file
		comment = readPubComment(filename + ".pub")
	}

	addedKey := &agent.AddedKey{
		PrivateKey: key,
		Comment:    "pouet pouet", /*comment*/
	}

	a := NewSshAgent()

	//create a temporary keychain
	tempKeychain := agent.NewKeyring()
	if err = tempKeychain.Add(*addedKey); err != nil {
		return err
	}

	lst, err := tempKeychain.List()
	if err != nil {
		return err
	}

	if len(lst) != 1 {
		return fmt.Errorf("wrong keychain List()")
	}

	l, err := a.keyring.List()
	if err != nil {
		return err
	}

	//check if the key was not already added by comparing pub keys
	for _, k := range l {
		if fingerprintSHA256(lst[0]) == fingerprintSHA256(k) {
			return fmt.Errorf("Key with fingerprint %v is already in the keychain. Not adding anything", fingerprintSHA256(k))
		}
	}

	mck := McKey{
		//		keyBlob:  req,
		addedKey: addedKey,
		pubKey:   lst[0],
	}
	a.Keys = append(a.Keys, mck)

	fmt.Println(mck.pubKey)

	//Send keys to moolticute
	//	if err := McSetKeys(a.ToMcKeys()); err != nil {
	//		return err
	//	}

	return
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

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
	"io/ioutil"
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

type ErrorCollector []error

func (c *ErrorCollector) Collect(e error) {
	*c = append(*c, e)
}

func (c *ErrorCollector) Error() (err string) {
	for _, e := range *c {
		err += fmt.Sprintf("%s\n", e.Error())
	}

	return err
}

func doCliAction(action string, keyNum int, filename []string) {
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
		if err := addKeys(filename); err != nil {
			jsonData = createJsonError(true, fmt.Sprintf("Failed to add key:\n%v", err.Error()))
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
	jarray = make([]JsonKey, 0)

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

	for i, mck := range a.Keys {
		pubKey, err := getPubKeyRaw(mck.PrivateKey, mck.Comment)
		if err != nil {
			return jarray, fmt.Errorf("Failed to get pub key for key #%d: %v", i, err)
		}

		jkey := JsonKey{
			PublicKey:   pubKey.String(),
			Fingerprint: fingerprintSHA256(pubKey) + " " + pubKey.Comment + " (" + pubKey.Format + ")",
		}

		pemblock := pemBlockForKey(mck.PrivateKey, pubKey)
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

	if keyNum < 0 {
		if err := a.removeAllKeys(true); err != nil {
			return fmt.Errorf("Failed to remove all keys: %v", err)
		}
	} else {
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

		if keyNum >= len(*k) {
			return fmt.Errorf("Error: %d is out of range. Only %d keys available.", keyNum, len(*k))
		}

		//found the key, delete it
		copy(a.Keys[keyNum:], a.Keys[keyNum+1:])
		a.Keys = a.Keys[:len(a.Keys)-1]

		//Send keys to moolticute
		if err := McSetKeys(a.ToMcKeys()); err != nil {
			return fmt.Errorf("Failed to remove key from moolticute: %v", err)
		}
	}

	return err
}

func addKeysCommand(filename []string) {
	if err := addKeys(filename); err != nil {
		fmt.Printf("Errors collected:\n%s", err.Error())
	} else {
		fmt.Println("Key added successfully")
	}
}

type AddKey struct {
	AddedKey *agent.AddedKey
	PubKey   *agent.Key
	Filename string
}

func addKeys(filename []string) (loadErrors ErrorCollector) {
	var newKeys []AddKey

	for _, f := range filename {
		fileData, err := ioutil.ReadFile(f)
		if err != nil {
			loadErrors.Collect(fmt.Errorf("[%s] Failed to read file, %v", f, err))
			continue
		}

		key, err := ssh.ParseRawPrivateKey(fileData)
		if err != nil {
			loadErrors.Collect(fmt.Errorf("[%s] Failed to parse, %v", f, err))
			continue
		}

		//Reparse the file and try to read the comment. The Golang api does
		// not export the comment field
		var comment string

		block, _ := pem.Decode(fileData)
		if block == nil {
			loadErrors.Collect(fmt.Errorf("[%s] No SSH keys found, %v", f, err))
			continue
		}

		switch block.Type {
		case "OPENSSH PRIVATE KEY":
			//In openssh format the comment is included inside the data block
			comment = readOpensshComment(block.Bytes)
		}

		if comment == "" {
			//try reading the comment from the .pub file
			comment = readPubComment(f + ".pub")
		}

		addedKey := &agent.AddedKey{
			PrivateKey: key,
			Comment:    comment,
		}

		//Get public key
		pubKey, err := getPubKey(addedKey)
		if err != nil {
			loadErrors.Collect(fmt.Errorf("Failed to get public key, %v", err))
			continue
		}

		//Check duplicated keys
		isDup := false
		for _, k := range newKeys {
			if fingerprintSHA256(pubKey) == fingerprintSHA256(k.PubKey) {
				loadErrors.Collect(fmt.Errorf("[%s] Key with fingerprint %v is a duplicate. Not adding this one", f, fingerprintSHA256(k.PubKey)))
				isDup = true
			}
		}

		if !isDup {
			newKeys = append(newKeys, AddKey{
				AddedKey: addedKey,
				PubKey:   pubKey,
				Filename: f,
			})
		}
	}

	if len(newKeys) == 0 {
		loadErrors.Collect(fmt.Errorf("No keys to add"))
		return
	}

	a := NewSshAgent()

	//Load keys from MC
	k, err := McLoadKeys()
	if err == nil {
		if err = a.addKeysToKeychain(k); err != nil {
			loadErrors.Collect(fmt.Errorf("Failed to load keys from Moolticute: %v\n", err))
			return
		} else {
			if len(*k) > 0 { //only set keys loaded if keys are present
				a.keysLoaded = true
			}
			log.Println(len(*k), "keys loaded from MP")
		}
	}

	l, err := a.keyring.List()
	if err != nil {
		loadErrors.Collect(fmt.Errorf("Failed to list keychain, %v", err))
		return
	}

	//check if the key was not already added by comparing pub keys
	aKeyWasAdded := false
	for _, ak := range newKeys {
		isAlreadyAdded := false
		for _, k := range l {
			log.Println("Comparing fingerprint", fingerprintSHA256(ak.PubKey), "==", fingerprintSHA256(k))
			if fingerprintSHA256(ak.PubKey) == fingerprintSHA256(k) {
				loadErrors.Collect(fmt.Errorf("[%s] This key with fingerprint %v is already in the keychain. Skipping.", ak.Filename, fingerprintSHA256(k)))
				isAlreadyAdded = true
			}
		}

		if !isAlreadyAdded {
			mck := AddedKeyToMcKey(ak.AddedKey)
			a.Keys = append(a.Keys, mck)
			aKeyWasAdded = true
		}
	}

	if !aKeyWasAdded {
		loadErrors.Collect(fmt.Errorf("Nothing to add. Aborting."))
		return
	}

	//Send keys to moolticute
	if err := McSetKeys(a.ToMcKeys()); err != nil {
		loadErrors.Collect(fmt.Errorf("Failed to send keys to device, %v", err))
	}

	return loadErrors
}

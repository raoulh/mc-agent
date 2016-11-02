package main

//SSH agent
//Most code comes from golang: golang.org/x/crypto/ssh/agent
//Modified to fit moolticute usage

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"reflect"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

const (
	agentRequestV1Identities   = 1
	agentRemoveAllV1Identities = 9

	// 3.2 Requests from client to agent for protocol 2 key operations
	agentAddIdentity         = 17
	agentRemoveIdentity      = 18
	agentRemoveAllIdentities = 19
	agentAddIdConstrained    = 25

	// 3.3 Key-type independent requests from client to agent
	agentAddSmartcardKey            = 20
	agentRemoveSmartcardKey         = 21
	agentLock                       = 22
	agentUnlock                     = 23
	agentAddSmartcardKeyConstrained = 26

	// 3.7 Key constraint identifiers
	agentConstrainLifetime = 1
	agentConstrainConfirm  = 2

	// maxAgentResponseBytes is the maximum agent reply size that is accepted. This
	// is a sanity check, not a limit in the spec.
	maxAgentResponseBytes = 16 << 20

	// 3.4 Generic replies from agent to client
	agentFailure = 5
	agentSuccess = 6
)

// See [PROTOCOL.agent], section 2.5.2.
const agentRequestIdentities = 11

type requestIdentitiesAgentMsg struct{}

// See [PROTOCOL.agent], section 2.5.2.
const agentIdentitiesAnswer = 12

type identitiesAnswerAgentMsg struct {
	NumKeys uint32 `sshtype:"12"`
	Keys    []byte `ssh:"rest"`
}

// See [PROTOCOL.agent], section 2.6.2.
const agentSignRequest = 13

type signRequestAgentMsg struct {
	KeyBlob []byte `sshtype:"13"`
	Data    []byte
	Flags   uint32
}

// See [PROTOCOL.agent], section 2.6.2.

// 3.6 Replies from agent to client for protocol 2 key operations
const agentSignResponse = 14

type signResponseAgentMsg struct {
	SigBlob []byte `sshtype:"14"`
}

type publicKey struct {
	Format string
	Rest   []byte `ssh:"rest"`
}

type wireKey struct {
	Format string
	Rest   []byte `ssh:"rest"`
}

type agentRemoveIdentityMsg struct {
	KeyBlob []byte `sshtype:"18"`
}

//struct for maintaining moolticute keys
type McKey struct {
	keyBlob  []byte
	addedKey *agent.AddedKey
	pubKey   *agent.Key
}

type SshAgent struct {
	keyring    agent.Agent
	keysLoaded bool //true if agent has already loaded keys from device

	//this is the raw list of keys loaded from MC, it is the
	//source for all keys sent to the keyring.
	Keys []McKey

	//mutex to prevent access from multiple place
	lock sync.Mutex

	//timer to clear keys
	timerClear *time.Timer
}

func NewSshAgent() *SshAgent {
	return &SshAgent{
		keyring: agent.NewKeyring(),
	}
}

func (a *SshAgent) processRequestBytes(reqData []byte) []byte {
	rep, err := a.processRequest(reqData)
	if err != nil {
		return []byte{agentFailure}
	}

	if err == nil && rep == nil {
		return []byte{agentSuccess}
	}

	return ssh.Marshal(rep)
}

func marshalKey(k *agent.Key) []byte {
	var record struct {
		Blob    []byte
		Comment string
	}
	record.Blob = k.Marshal()
	record.Comment = k.Comment

	return ssh.Marshal(&record)
}

func (a *SshAgent) processRequest(data []byte) (interface{}, error) {
	switch data[0] {
	case agentSignRequest:
		log.Println("Signing request")
		var req signRequestAgentMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		k := &agent.Key{
			Format: wk.Format,
			Blob:   req.KeyBlob,
		}

		sig, err := a.keyring.Sign(k, req.Data) //  TODO(hanwen): flags.
		if err != nil {
			return nil, err
		}
		return &signResponseAgentMsg{SigBlob: ssh.Marshal(sig)}, nil

	case agentRequestIdentities:
		log.Println("Requesting identities")
		keys, err := a.keyring.List()
		if err != nil {
			return nil, err
		}

		rep := identitiesAnswerAgentMsg{
			NumKeys: uint32(len(keys)),
		}
		for _, k := range keys {
			rep.Keys = append(rep.Keys, marshalKey(k)...)
		}
		return rep, nil

	case agentAddIdentity:
		log.Println("Adding a new identity")
		return nil, a.insertIdentity(data)

	case agentRemoveIdentity:
		var req agentRemoveIdentityMsg
		if err := ssh.Unmarshal(data, &req); err != nil {
			return nil, err
		}

		var wk wireKey
		if err := ssh.Unmarshal(req.KeyBlob, &wk); err != nil {
			return nil, err
		}

		l, err := a.keyring.List()
		if err != nil {
			return nil, err
		}

		keyToDel := agent.Key{Format: wk.Format, Blob: req.KeyBlob}

		//find the key
		for i, k := range l {
			if reflect.DeepEqual(k, keyToDel) {
				//found the key, delete it
				copy(a.Keys[i:], a.Keys[i+1:])
				a.Keys[len(a.Keys)-1].addedKey = nil //do not leak
				a.Keys[len(a.Keys)-1].pubKey = nil   //do not leak
				a.Keys = a.Keys[:len(a.Keys)-1]
				break
			}
		}

		return nil, a.keyring.Remove(&keyToDel)

	case agentRemoveAllIdentities:
		log.Println("Remove all identities")
		return nil, a.removeAllKeys(true)
	}

	return nil, fmt.Errorf("Not implemented opcode %d", data[0])
}

//process a SSH agent request
func (a *SshAgent) ProcessRequest(c io.ReadWriter) error {

	a.lock.Lock()
	defer a.lock.Unlock()

	var length [4]byte

	if _, err := io.ReadFull(c, length[:]); err != nil {
		return err
	}
	l := binary.BigEndian.Uint32(length[:])
	if l > maxAgentResponseBytes {
		// We also cap requests.
		return fmt.Errorf("agent: request too large: %d", l)
	}

	req := make([]byte, l)
	if _, err := io.ReadFull(c, req); err != nil {
		return err
	}

	//load keys from moolticute if not done, or after timeout
	if !a.keysLoaded {
		log.Println("Ask MC keys")
		k, err := McLoadKeys()
		if err == nil {
			a.keysLoaded = true

			if err = a.addKeysToKeychain(k); err != nil {
				return fmt.Errorf("Failed to load keys from Moolticute: %v", err)
			} else {
				log.Println(len(*k), "keys loaded from MP")
			}
		}
	}

	//start timer to clear keys
	if a.timerClear != nil {
		if !a.timerClear.Stop() {
			<-a.timerClear.C //drain value from the channel
		}
		a.timerClear.Reset(time.Duration(timeoutClearKeys))
	} else {
		a.timerClear = time.NewTimer(time.Duration(timeoutClearKeys))
	}
	go func() {
		<-a.timerClear.C
		a.timerClear = nil
		log.Println("Timer expires, clear keys")

		a.lock.Lock()
		defer a.lock.Unlock()

		if err := a.removeAllKeys(false); err != nil {
			log.Println("Failed to remove all keys:", err)
		}

		a.keysLoaded = false
	}()

	repData := a.processRequestBytes(req)
	if len(repData) > maxAgentResponseBytes {
		return fmt.Errorf("agent: reply too large: %d bytes", len(repData))
	}

	binary.BigEndian.PutUint32(length[:], uint32(len(repData)))
	if _, err := c.Write(length[:]); err != nil {
		return err
	}
	if _, err := c.Write(repData); err != nil {
		return err
	}

	return nil
}

//add all keys from MC to keychain
func (a *SshAgent) addKeysToKeychain(keys *McBinKeys) error {
	//Populate the keyring with all keys loaded from MP
	for i := 0; i < len(*keys); i++ {
		if err := a.addKeyFromMoolticute([][]byte(*keys)[i]); err != nil {
			return fmt.Errorf("Failed to load key %d: %v", i, err)
		}
	}

	return nil
}

//add a key to the keychain
func (a *SshAgent) addKeyFromMoolticute(req []byte) error {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(req, &record); err != nil {
		return err
	}

	var addedKey *agent.AddedKey
	var err error

	switch record.Type {
	case ssh.KeyAlgoRSA:
		addedKey, err = parseRSAKey(req)
	case ssh.KeyAlgoDSA:
		addedKey, err = parseDSAKey(req)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		addedKey, err = parseECDSAKey(req)
	case ssh.KeyAlgoED25519:
		addedKey, err = parseEd25519Key(req)
	case ssh.CertAlgoRSAv01:
		addedKey, err = parseRSACert(req)
	case ssh.CertAlgoDSAv01:
		addedKey, err = parseDSACert(req)
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		addedKey, err = parseECDSACert(req)
	case ssh.CertAlgoED25519v01:
		addedKey, err = parseEd25519Cert(req)
	default:
		return fmt.Errorf("agent: not implemented: %q", record.Type)
	}
	if err != nil {
		return err
	}
	return a.keyring.Add(*addedKey)
}

//insert an identity into keychain
func (a *SshAgent) insertIdentity(req []byte) error {
	var record struct {
		Type string `sshtype:"17|25"`
		Rest []byte `ssh:"rest"`
	}

	if err := ssh.Unmarshal(req, &record); err != nil {
		return err
	}

	var addedKey *agent.AddedKey
	var err error

	switch record.Type {
	case ssh.KeyAlgoRSA:
		addedKey, err = parseRSAKey(req)
	case ssh.KeyAlgoDSA:
		addedKey, err = parseDSAKey(req)
	case ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		addedKey, err = parseECDSAKey(req)
	case ssh.KeyAlgoED25519:
		addedKey, err = parseEd25519Key(req)
	case ssh.CertAlgoRSAv01:
		addedKey, err = parseRSACert(req)
	case ssh.CertAlgoDSAv01:
		addedKey, err = parseDSACert(req)
	case ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01:
		addedKey, err = parseECDSACert(req)
	case ssh.CertAlgoED25519v01:
		addedKey, err = parseEd25519Cert(req)
	default:
		return fmt.Errorf("agent: not implemented: %q", record.Type)
	}
	if err != nil {
		return err
	}

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
		if reflect.DeepEqual(k, lst[0]) {
			log.Println("Key already in keychain")
			return nil
		}
	}

	mck := McKey{
		keyBlob:  req,
		addedKey: addedKey,
		pubKey:   lst[0],
	}
	a.Keys = append(a.Keys, mck)

	//Send keys to moolticute
	if err := McSetKeys(a.ToMcKeys()); err != nil {
		return err
	}

	return a.keyring.Add(*addedKey)
}

func (a SshAgent) ToMcKeys() *McBinKeys {
	var k McBinKeys
	for i := 0; i < len(a.Keys); i++ {
		k = append(k, a.Keys[i].keyBlob)
	}
	return &k
}

func (a SshAgent) removeAllKeys(delFromDevice bool) error {
	a.Keys = nil //clear keys

	if delFromDevice {
		//Send keys to moolticute
		if err := McSetKeys(a.ToMcKeys()); err != nil {
			return fmt.Errorf("Failed to remove keys from moolticute: %v", err)
		}
	}

	return a.keyring.RemoveAll()
}

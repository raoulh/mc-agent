package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"

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

type SshAgent struct {
	keyring    agent.Agent
	keysLoaded bool //true if agent has already loaded keys from device
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
	case agentRequestIdentities:
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
	}

	return nil, fmt.Errorf("Not implemented opcode %d", data[0])
}

func (a *SshAgent) ProcessRequest(c io.ReadWriter) error {
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

	if !a.keysLoaded {
		log.Println("Ask MC keys")
		k, err := McLoadKeys()
		if err == nil {
			a.keysLoaded = true
			log.Println(len(*k), "keys loaded from MP")

			//Populate the keyring with all keys loaded from MP
			//TODO: unmarshal keys based on https://github.com/golang/crypto/blob/master/ssh/agent/client.go#L439
		}
	}

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

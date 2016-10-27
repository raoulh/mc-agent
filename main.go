// +build go1.7

package main

import (
	"runtime"

	"golang.org/x/crypto/ssh/agent"
)

const (
	CONN_HOST = "localhost"
	CONN_PORT = "3333"
	CONN_TYPE = "tcp"
)

var (
	keyring agent.Agent
)

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	keyring = agent.NewKeyring()

	RunAgent()

	//go agent.ServeAgent(keyring, )
}

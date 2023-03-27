//go:build !windows
// +build !windows

// Agent platform code for Linux and macOS
// Listens to a unix socket
package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"syscall"

	cli "github.com/jawher/mow.cli"
)

var (
	sshAgent *SshAgent

	sockPath *string
	sockDir  string
	noFork   *bool
)

func SetupPlatformOpts(app *cli.Cli) {
	app.Spec = app.Spec + "[-a][-n]"

	sockPath = app.StringOpt("a address", "", "Bind to this socket address")
	noFork = app.BoolOpt("n no-fork", false, "Do not fork in background, use this with systemd")
}

func RunAgent() {
	// parse/create socket path
	if *sockPath == "" {
		// create socket path
		os.TempDir()
		sockDir, err := os.MkdirTemp("", "moolticute-ssh-agent")
		if err != nil {
			log.Fatal(err)
		}

		*sockPath = sockDir + "/agent.sock"
	}

	if !*noFork {
		args := append(os.Args[1:], "--no-fork", "--address="+*sockPath)
		cmd := exec.Command(os.Args[0], args...)
		if err := cmd.Start(); err != nil {
			log.Fatal(err)
		}
		echoSocket(*sockPath)
		return
	}

	log.Println("Starting Moolticute SSH agent")

	sshAgent = NewSshAgent()

	l, err := net.Listen("unix", *sockPath)
	if err != nil {
		log.Fatal("listen error:", err)
	}

	// cleanly shutdown in case a signal has been received
	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	go func(c chan os.Signal) {
		sig := <-c
		fmt.Printf("Caught signal %s: shutting down.\n", sig)
		// Stop listening and unlink the socket:
		l.Close()
		os.RemoveAll(sockDir) // clean up

		os.Exit(0)
	}(sigc)

	echoSocket(*sockPath)

	for {
		fd, err := l.Accept()
		if err != nil {
			log.Fatal("accept error:", err)
		}

		go handleClient(fd)
	}
}

func handleClient(fd net.Conn) {
	for {
		if err := sshAgent.ProcessRequest(fd); err != nil {
			log.Println("Failed:", err)
			break
		}
	}
}

func echoSocket(p string) {
	fmt.Printf("SSH_AUTH_SOCK=%s; export SSH_AUTH_SOCK;\n", p)
}

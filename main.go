// +build go1.7

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/jawher/mow.cli"
)

const (
	CharStar     = "\u2737"
	CharAbort    = "\u2718"
	CharCheck    = "\u2714"
	CharWarning  = "\u26A0"
	CharArrow    = "\u2012\u25b6"
	CharVertLine = "\u2502"
)

var (
	timeoutClearKeys Duration = Duration(time.Minute * 15)
	mcUrl            *string
	debugOpt         *bool
	cliAction        *string
	outputProgress   *bool //used by moolticute for loading keys into gui
	listFingerprints *bool
	keyNumber        *int
)

// Declare Duration type for CLI
type Duration time.Duration

// Make it implement flag.Value
func (d *Duration) Set(v string) error {
	parsed, err := time.ParseDuration(v)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d *Duration) String() string {
	duration := time.Duration(*d)
	return duration.String()
}

func exit(err error, exit int) {
	fmt.Fprintln(os.Stderr, CharAbort, err)
	cli.Exit(exit)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.App("mc-agent", "SSH agent that use moolticute to store/load your keys")

	app.Spec = "[-d][-m][--debug][-p]"

	app.VarOpt("d duration", &timeoutClearKeys, "How long you want the agent to keep keys into memory (default to 15min)")
	mcUrl = app.StringOpt("m moolticute_url", MOOLTICUTE_DAEMON_URL, "Use a different url for connecting to moolticute")
	debugOpt = app.BoolOpt("debug", false, "Add debug log to stdout")
	outputProgress = app.BoolOpt("p output_progress", false, "Used by moolticute GUI")
	//	printPriv = app.IntOpt("private_key", 0, "Print the private key n in PEM format")

	SetupPlatformOpts(app)

	app.Command("public", "List public key parameters of all identities", func(cmd *cli.Cmd) {
		var (
			listFingerprints = cmd.BoolOpt("l", false, "List fingerprints of all identities instead of public keys")
			keyNumber        = cmd.IntArg("KEYNUM", -1, "Select which key to output, default displays all keys")
		)

		cmd.Spec = "[KEYNUM] [OPTIONS]"

		cmd.Action = func() {
			setupLogger()
			if *listFingerprints {
				listKeysCommand(ListPubFinger, *keyNumber)
			} else {
				listKeysCommand(ListPublicKeys, *keyNumber)
			}
		}
	})

	app.Command("private", "Print the private key in PEM format", func(cmd *cli.Cmd) {
		var (
			keyNumber = cmd.IntArg("KEYNUM", 0, "Select which key to output")
		)

		cmd.Spec = "[KEYNUM]"

		cmd.Action = func() {
			setupLogger()
			listKeysCommand(ListPrivKey, *keyNumber)
		}
	})

	app.Command("cli", "CLI API to play with keys from within the moolticute GUI", func(cmd *cli.Cmd) {
		var (
			cliAction = cmd.StringOpt("c cli_action", "", "CLI API to play with keys from within the moolticute GUI")
		)

		cmd.Action = func() {
			setupLogger()
			doCliAction(*cliAction)
		}
	})

	//Main action of the tool is to start the Agent
	app.Action = func() {
		setupLogger()
		RunAgent()
	}

	if err := app.Run(os.Args); err != nil {
		exit(err, 1)
	}
}

func setupLogger() {
	if !*debugOpt {
		//completely disable debug output
		log.SetFlags(0)
		log.SetOutput(ioutil.Discard)
	}
}

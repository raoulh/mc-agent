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

	app := cli.App("moolticute_ssh-agent", "SSH agent that use moolticute to store/load your keys")

	app.Spec = "[-d][-m][--debug]"

	app.VarOpt("d duration", &timeoutClearKeys, "How long you want the agent to keep keys into memory (default to 15min)")
	mcUrl = app.StringOpt("m moolticute_url", MOOLTICUTE_DAEMON_URL, "Use a different url for connecting to moolticute")
	debugOpt = app.BoolOpt("debug", false, "Add debug log to stdout")

	SetupPlatformOpts(app)

	app.Action = func() {
		if !*debugOpt {
			//completely disable debug output
			log.SetFlags(0)
			log.SetOutput(ioutil.Discard)
		}
		RunAgent()
	}

	if err := app.Run(os.Args); err != nil {
		exit(err, 1)
	}
}

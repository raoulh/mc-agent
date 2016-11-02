// +build go1.7

package main

import (
	"fmt"
	"os"
	"runtime"
	"time"

	"github.com/fatih/color"
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

	blue       = color.New(color.FgBlue).SprintFunc()
	errorRed   = color.New(color.FgRed).SprintFunc()
	errorBgRed = color.New(color.BgRed, color.FgBlack).SprintFunc()
	green      = color.New(color.FgGreen).SprintFunc()
	cyan       = color.New(color.FgCyan).SprintFunc()
	bgCyan     = color.New(color.FgWhite).SprintFunc()
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
	fmt.Fprintln(os.Stderr, errorRed(CharAbort), err)
	cli.Exit(exit)
}

func main() {
	runtime.GOMAXPROCS(runtime.NumCPU())

	app := cli.App("moolticute-ssh-agent", "SSH agent that use moolticute to store/load your keys")

	app.Spec = "[-d][-m]"

	app.VarOpt("d duration", &timeoutClearKeys, "How long you want the agent to keep keys into memory (default to 15min)")
	mcUrl = app.StringOpt("m moolticute_url", MOOLTICUTE_DAEMON_URL, "Use a different url for connecting to moolticute")

	app.Action = func() {
		color.Blue(CharArrow + " Starting moolticute SSH agent")
		RunAgent()
	}

	if err := app.Run(os.Args); err != nil {
		exit(err, 1)
	}
}

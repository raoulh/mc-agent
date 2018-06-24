// +build linux darwin

package main

const (
  LongHelpText = `SSH agent that uses moolticute to store/load your keys

An easy way to setup is to enable the "Autostart SSH Agent" setting in the Moolticute app, and set
the "Moolticute SSH Arguments" to something like:

  --address /tmp/mc-agent.socket

After which mc-agent will be automatically used if the following is added to .bashrc (or similar):

  export SSH_AUTH_SOCK=/tmp/mc-agent.socket

For more information: https://github.com/raoulh/mc-agent/blob/master/docs/mc-agent.md`
)

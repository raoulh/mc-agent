Moolticute ssh-agent
====================

[![License](https://img.shields.io/badge/license-GPLv3%2B-blue.svg)](http://www.gnu.org/licenses/gpl.html)

This tool is an ssh-agent that replaces your standard ssh-agent (openssh, Pageant or agent from macOS) and loads all your keys that are stored on your mooltipass device. It connects to a [Moolticute](https://github.com/raoulh/moolticute "Moolticute") daemon whenever someone needs to connect to a ssh server. The keys are not kept inside memory for a long time, and you need to accept the access from the Mooltipass device.

It is completely cross platform. On linux/macOS it replaces any existing ssh-agent by listening to a local socket. On Windows it emulates the Putty Pageant software, so any existing software that can talk to Pageant will work with moolticute_ssh-agent. 

> Warning! This project is a work in progress!
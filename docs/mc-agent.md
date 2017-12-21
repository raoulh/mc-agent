# mc-agent
## Introduction
mc-agent is built by [Mooltipass](https://www.themooltipass.com/
"Mooltipass website") community in order to provide a tool that
comply to the
[ssh-agent](https://tools.ietf.org/html/draft-miller-ssh-agent-00#section-1
"SSH-agent reference") standard from the OpenSSH project.
mc-agent provide the ability to load and store private key that are used for
authentication using the [SSH](https://www.openssh.com/specs.html
"OpenSSH specification") protocol into the Mooltipass thanks to its
[file-system capability](https://github.com/limpkin/mooltipass/tree/master/source_code/src/NODEMGMT
"Mooltipass file-system capability"). The "SSH key" must be loaded into the user database
inside the Mooltipass (see below how) and will be automatically used when
an SSH client try to authenticate with an SSH server. Note that like any sensitive
operation, a physical check must be performed on the Mooltipass before the key
is released to the agent.
Once the key has move from the Mooltipass to the agent it will be keep in
the mc-agent memory for a configurable period of time.
On the Windows platform, mc-agent fully replaces the Putty SSH agent. Thus all Putty compatible tools
can be used transparently with mc-agent.

### ssh-agent
ssh-agent are used to store the unencrypted format of key used for authenticating
against SSH server. That is, one is able to permanently store its key in a "secure
way" (encrypted on disk, security tokens, Mooltipass), with only need to provided
material for getting its non-encrypted version one. Basically, the encrypted key
is loaded into the ssh-agent memory, and the ssh client use the agent to provide
authentication material to SSH server. Dialog between the ssh-agent and the ssh
client is made using [UNIX domain
socket](https://en.wikipedia.org/wiki/Unix_domain_socket "Unix domain socket").

## Usage
In order to benefit from the file storing capability of the Mooltipass, mc-agent
rely on [Moolticute](https://github.com/mooltipass/moolticute
"Moolticute source code") as an abstraction to the Mooltipass, thus Moolticute must
be properly installed and running in order to use mc-agent.

## Installation
mc-agent is distributed with the moolticute official installer. If you are not using
those binaries, you can either get a copy of the binary of mc-agent from this [download page](https:/calaos.fr/mooltipass/tools).
Installation from source can be done with go with something like:

```
$ go get github.com/raoulh/mc-agent
```

## Usage on Linux/macOS

Once [mc-agent](https://github.com/raoulh/mc-agent "mc-agent source
code") binary is installed in your system the following consider it is
accessible within your PATH. The agent behaves like a standard ssh-agent.
It can be started the same way and it will export the standard SSH_AUTH_SOCK env variable.

To start it normally by using a random socket path:

```
$ mc-agent
SSH_AUTH_SOCK=/tmp/moolticute-ssh-agent404882600/agent.sock; export SSH_AUTH_SOCK;
```

The agent will fork in the background.

One common way of starting an ssh-agent is to put this in your .bashrc:
```
if ! pgrep -u "$USER" mc-agent > /dev/null; then
    mc-agent > ~/.mc-agent-env
fi
if [[ "$SSH_AUTH_SOCK" == "" ]]; then
    eval "$(<~/.mc-agent-env)"
fi
```

That will start automatically the mc-agent once, and reuse the existing running one in all
terminal you open after.

### Add/List/Delete keys

To manage keys in your mooltipass device, multiple ways can be used. One can use the standard `ssh-add`
command.

Add a key:
```
$ ssh-add my-key-file.key
```
Delete all keys:
```
$ ssh-add -D
```
List keys:
```
$ ssh-add -l
```

Another way is to directly use `mc-agent` from the terminal.
Add a key:
```
$ mc-agent add my-key-file.key my_other_key
```
Delete all keys:
```
$ mc-agent delete -a
```
List public keys:
```
$ mc-agent public
```

For the help of all command available in mc-agent please check:
```
$ mc-agent [command] --help
```

A third way of managing keys in your device is to use the Moolticute application.

## Usage on Windows

On windows, the agent emulates Putty agent. You need to stop pageant.exe (the putty agent) as mc-agent.exe replaces it. The agent can simply be started by checking *start ssh agent* in the moolticute app (settings tab). After a restart the agent should be running (check in Task manager). The usage is simple: just run Putty and it will connect to the agent.

### Cygwin/Msys
If you are using cygwin or msys and want to use the ssh-agent from there, it's a bit more complicated as it requires another layer: ssh-pageant. You can grab it from here: https://github.com/cuviper/ssh-pageant
Then in your terminal, you would need to start this proxy in your .bashrc config file by running:
eval $(/usr/bin/ssh-pageant -r -a "/tmp/.ssh-pageant-$USERNAME")
After that ssh from your cygwin/msys installation would use ssh-pageant -> mc-agent -> moolticuted -> your device :)

### Windows WSL (Windows Subsystem for Linux)

If you are using WSL and bash under Windows, you can follow the Linux procedure. `mc-agent` will run as a linux process and it will connect to the moolticuted.exe running as a windows process. Everything is straightforward.

## macOS Specifics

On osx, by default the system runs an ssh-agent that connects with Keyring for the key storage. For now I did not do any work on how to replace (disable it) the system agent with moolticute agent (help welcome). The agent should be started by hand in a terminal:
eval $(/Applications/Moolticute.app/Contents/MacOS/mc-agent --address /tmp/mc-agent.socket)

In your other terminal you can first do:
export SSH_AUTH_SOCK=/tmp/mc-agent.socket

Then any ssh command typed in the terminal (that uses the correctly exported SSH_AUTH_SOCK) would use moolticute agent.

## Notes

> Note that if one need to use-back the classical ssh-agent just changed the value
> of the SSH_AUTH_SOCK environment variable will do the tricks:
> ```
> $ readonly _MC_AGENT_SOCK=/tmp/moolticute-ssh-agent693404146/agent.sock
> $ readonly  _SSH_AGENT_SOCK=/dev/shm/user/ssh-hEGNcVM1Dk1Q/agent.27852
> 
> $ SSH_AUTH_SOCK="${_SSH_AGENT_SOCK}" ssh-add -l
> 256 SHA256:aUoc2OHexFL8E/JcJ/dAxG/Rt7Y+t7YkdaIjki/dLhE user@loulou (ED25519)
> $ SSH_AUTH_SOCK="${_MC_AGENT_SOCK}" ssh-add -l
> 2048 SHA256:vKkojvCuXc++hPmzUZgngU74FrHgoWhqiYeB7sCSxGs mpm (RSA)
> ```

> Note that, for simplicity an systemd service file is provided
> [upstream](https://github.com/raoulh/mc-agent/blob/master/systemd/moolticute-ssh-agent.service "systemd unit file")
> that could be run and enabled for non-privileged users:
> ```
> $ systemctl --user start mc-agent.service
> $ systemctl --user enable mc-agent.service
> ```

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

### ssh-agent
ssh-agent are used to store the unencrypted format of key used for authenticating
against SSH server. That it, one is able to permanently store its key in a "secure
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
be properly installed and running in order to use mc-agent. This is outside of this
scope and here, we will admit that Moolticute is listening on port TCP/30035.

Once [mc-agent](https://github.com/raoulh/mc-agent "mc-agent source
code") binary is installed in your system the following consider it is
accessible within your PATH. We will launch the agent which will print on its
standard output the path of the created socket:

```
$ mc-agent
SSH_AUTH_SOCK=/tmp/moolticute-ssh-agent404882600/agent.sock; export SSH_AUTH_SOCK;
```

One way to directly benefit from this is to eval the output of mc-agent:
```
$ pkill mc-agent
$ eval "$(mc-agent)"
```
We can ensure that our agent has no identity loaded yet:
```
$ ssh-add -l
The agent has no identities.
```
Above command will reflect something like the following in moolticuted logs:
```
DEBUG: :0 - New connection
DEBUG: :0 - JSON API recv: {"msg":"get_data_node","data":{"service":"Moolticute SSH Keys"},"client_id":"7353a5e0-1f0c-4562-b019-640ecd5fc389"}
DEBUG: :0 - Connection closed  WSServerCon(0xbe4377030d0)
```
The next step is to generate dummy SSH key, load-it into mc-agent, which will
store into our Mooltipass.
```
$ ssh-keygen -t rsa -f mpm_ssh_key.rsa.ssh
Generating public/private rsa key pair.
Enter passphrase (empty for no passphrase):
Enter same passphrase again:
Your identification has been saved in mpm_ssh_key.rsa.ssh.
Your public key has been saved in mpm_ssh_key.rsa.ssh.pub.
The key fingerprint is:
SHA256:aUoc2OHexFL8E/JcJ/dAxG/Rt7Y+t7YkdaIjki/dLhE user@loulou
The key's randomart image is:
+--[ED25519 256]--+
|      ...    +o .|
|     + +o . o =.o|
|    . = o= o + ++|
|     o = .E    o+|
|      + S  o  ooo|
|     . o ..  ..o.|
|      . o..oo... |
|        .oo...o+.|
|         ..o. .o=|
+----[SHA256]-----+

$ ssh-add mpm_ssh_key.rsa.ssh
Enter passphrase for mpm_ssh_key.rsa.ssh:
Identity added: mpm_ssh_key.rsa.ssh (user@lxc00)

$ shred -n 3 -u mpm_ssh_key.rsa.ssh
```
Note that before upload the private key into the Mooltipass a physical validation
has to be made on the device

The private part of the key is now loaded into the Mooltipass and our agent:
```
$ ssh-add -l
2048 SHA256:vKkojvCuXc++hPmzUZgngU74FrHgoWhqiYeB7sCSxGs mpm (RSA)
```
The public part could now be used to issue [SSH
certificates](https://cvsweb.openbsd.org/cgi-bin/cvsweb/src/usr.bin/ssh/PROTOCOL.certkeys?annotate=HEAD
"OpenSSH certificate") or to placed into
authorized_keys file for client authentication purpose. Note that once the private
key has been loaded into the agent one could easily retrieve the public part using
'ssh-add -L'.
Once the public part has been uploaded to our SSH server the last step is to
configure our SSH client. I like the fact that the client only send the key
used for authentication on a specific server (not all key loaded into the agent).

The following could apply to /etc/ssh/ssh_config
```
Host *
        IdentitiesOnly     yes
```
Whereas, the following could apply to ~/.ssh/config
```
Host test_mc_agent
        IdentityFile ~/mpm_ssh_key.rsa.rsa.ssh.pub
```

Then try to connect to the configured server, the agent will be queried to issue
private material and the authentication will succeed.

```
$ ssh test_mc_agent
```

Note that if one need to use-back the classical ssh-agent just changed the value
of the SSH_AUTH_SOCK environment variable will do the tricks:
```
$ readonly _MC_AGENT_SOCK=/tmp/moolticute-ssh-agent693404146/agent.sock
$ readonly  _SSH_AGENT_SOCK=/dev/shm/user/ssh-hEGNcVM1Dk1Q/agent.27852

$ SSH_AUTH_SOCK="${_SSH_AGENT_SOCK}" ssh-add -l
256 SHA256:aUoc2OHexFL8E/JcJ/dAxG/Rt7Y+t7YkdaIjki/dLhE user@loulou (ED25519)
$ SSH_AUTH_SOCK="${_MC_AGENT_SOCK}" ssh-add -l
2048 SHA256:vKkojvCuXc++hPmzUZgngU74FrHgoWhqiYeB7sCSxGs mpm (RSA)
```
Note that, for simplicity an systemd service file is provided
[upstream](https://github.com/raoulh/mc-agent/blob/master/systemd/moolticute-ssh-agent.service
"systemd unit file") that could be run and enabled
for non-privileged users:
```
$ systemctl --user start mc-agent.service
$ systemctl --user enable mc-agent.service
```

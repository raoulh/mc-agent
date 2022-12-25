# init

## Systemd

It is possible to start moolticute_ssh-agent with systemd user.
To do so, copy the [`moolticute-ssh-agent.service`](mc-agent.service) file
to `~/.config/systemd/user/moolticute-ssh-agent.service`

### Start service

Enable and start the service with

```console
systemctl --user enable --now moolticute-ssh-agent
```

The agent will be started immediately and automatically with your session.

### Environment variable

You also need to export the corresponding env var to let other software use the agent. Add `export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/moolticute-ssh-agent.socket"` to your shell startup file (`~/.bashrc` or `~/.zshrc`) or set that env var in your desktop environment configuration.

## Launchctl

Copy the [`com.themooltipass.moolticute-ssh-agent.plist`](com.themooltipass.moolticute-ssh-agent.plist) file to `~/Library/LaunchAgents/com.themooltipass.moolticute-ssh-agent.plist`
Replace all three instances of `{{ user }}` with your username.

### Load

Load the service to start on boot

```console
launchctl load -w ~/Library/LaunchAgents/com.themooltipass.moolticute-ssh-agent.plist
```

```console
launchctl start com.themooltipass.moolticute-ssh-agent
```

### Environment

Add `$SSH_AUTH_SOCK=$HOME/Library/Application Support/moolticute-ssh-agent.socket`
to your shell configuration or desktop environment to use the agent.

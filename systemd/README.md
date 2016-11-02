# Systemd #

It is possible to start moolticute_ssh-agent with systemd user. To do so, copy the `moolticute-ssh-agent.service` file to `~/.config/systemd/user/moolticute-ssh-agent.service`

### Start service ###
Enable and start the service with
```
systemctl enable moolticute-ssh-agent
systemctl start moolticute-ssh-agent
```

The agent will be started automatically with your session.

### Environment variable ###
You also need to export the corresponding env var to let other software use the agent. Add `export SSH_AUTH_SOCK="$XDG_RUNTIME_DIR/moolticute-ssh-agent.socket"` to your shell startup file (`~/.bashrc` or `~/.zshrc` for example or set that env var in your desktop environment configuration)


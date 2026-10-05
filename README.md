# wireguard-spoke-agent

Keeps a Windows WireGuard spoke's tunnel installed, current with [wireguard-hub](https://github.com/AetherBreaker/wireguard-hub)'s releases, and running. It only manages the WireGuard service. Each spoke installs it its own way (for example camera-footage-fs's installer).

## On the PC

Everything lives in `C:\ProgramData\wireguard-spoke-agent\` (SYSTEM and Administrators only):

- `settings.env`: `WG_PEER_NAME`, `PERSISTED_DIR_LOC`, and the optional `PINGKEY` / `HEARTBEAT_SLUG` / `ALERTS_HEALTHCHECK_PING_URL` / `ALERTS_PUSHOVER_TOKEN` / `ALERTS_PUSHOVER_USER_KEY`. Loaded into the agent's own environment before aeth-ext is imported. Until aeth-ext treats a missing `ALERTS_EMAIL_PWD` as "email off", it must also hold `ALERTS_EMAIL_PWD=unused` and `ALERTS_RECIPIENTS=[]`. The second line stops any SMTP login with the placeholder.
- `<peer>.key`: the peer's WireGuard private key. `<peer>.conf` is the filled-in conf the tunnel service was installed from.
- `uv\`, `python\`, `tools\`, `bin\`, `cache\`: uv and the agent's uv-managed install.
- `run.cmd` and the scheduled task `wireguard-spoke-agent` (SYSTEM, at boot and every 5 minutes) are rendered from this package's templates and kept in sync by the agent.
- `state.json`: the last applied hub tag, the task template hash, and any pending `--python` move. `logs\`: `agent.log` and `upgrade.log`.

What a run does is in the module docstring of `src/wireguard_spoke_agent/__main__.py`.

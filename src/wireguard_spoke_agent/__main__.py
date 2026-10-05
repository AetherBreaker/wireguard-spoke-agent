"""`wireguard-spoke-agent [install]`: keeps a Windows spoke's WireGuard tunnel current and running.

Run every 5 minutes as SYSTEM by its scheduled task, through `run.cmd` (which upgrades the agent
first). Each run:

1. Loads `settings.env` from the locked home folder into this process's environment. This must
   precede any aeth-ext import: aeth-ext validates its settings at import.
2. Asks the hub for its release tag. On a new tag, fetches this peer's conf from that GitHub
   release, fills in the private key, and reinstalls the tunnel service only if the conf changed.
3. Makes sure the tunnel service exists and is running.
4. Pings healthchecks.io with the handshake's freshness, when a ping key or URL is configured.
5. Re-renders `run.cmd` and the scheduled task from the package templates when they differ, adding
   `--python 3.N` to the upgrade when the newest release needs a newer Python than this one.

Uncaught exceptions go to aeth-ext's fatal handler, which sends the Pushover alert.
`install` (run once by the spoke's own installer) renders `run.cmd`, registers the task and runs once.
"""

# Standard library imports
import hashlib
import html
import json
import logging
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request
from importlib.resources import files
from logging.handlers import RotatingFileHandler
from pathlib import Path

HOME = Path(r"C:\ProgramData\wireguard-spoke-agent")
SETTINGS_FILE = HOME / "settings.env"
STATE_FILE = HOME / "state.json"
RUN_CMD = HOME / "run.cmd"
TASK_XML = HOME / "task.xml"
LOG_FILE = HOME / "logs" / "agent.log"
TASK_NAME = "wireguard-spoke-agent"

HUB_VERSION_URL = "https://tunnels.sweetfiretobacco.com/version"
HUB_CONF_URL = "https://github.com/AetherBreaker/wireguard-hub/releases/download/{tag}/{peer}.conf"
INDEX_URL = "https://pypi.sweetfiretobacco.com/jacob.ogden/internal/+simple/wireguard-spoke-agent/"
KEY_PLACEHOLDER = "REPLACE_WITH_THIS_PEERS_PRIVATE_KEY"

WIREGUARD = Path(r"C:\Program Files\WireGuard\wireguard.exe")
WG = Path(r"C:\Program Files\WireGuard\wg.exe")
SERVICE_MISSING = 1060  # sc.exe's ERROR_SERVICE_DOES_NOT_EXIST
STALE_SECS = 180  # the container spokes' WG_STALE_SECS default
SETTLE_SECS = 60  # how long a just-(re)started tunnel gets to handshake before it's judged
HTTP_TIMEOUT_SECS = 15

log = logging.getLogger("wireguard_spoke_agent")


def load_settings() -> None:
  """Read `settings.env` (`KEY=value` lines, `#` comments) into this process's environment."""
  for raw in SETTINGS_FILE.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if line and not line.startswith("#"):
      key, _, value = line.partition("=")
      os.environ[key.strip()] = value.strip()


def http_get(url: str) -> str:
  """GET *url* and return its body as text."""
  req = urllib.request.Request(url, headers={"User-Agent": "wireguard-spoke-agent"})  # noqa: S310 - fixed https URLs
  with urllib.request.urlopen(req, timeout=HTTP_TIMEOUT_SECS) as resp:  # noqa: S310
    return resp.read().decode("utf-8")


def sc(*args: str) -> subprocess.CompletedProcess[str]:
  """Run `sc.exe` without raising; callers read the return code."""
  return subprocess.run(["sc.exe", *args], capture_output=True, text=True, check=False)


def install_tunnel(peer: str, conf: Path) -> None:
  """(Re)install the tunnel service from *conf* and have Windows restart it if it crashes."""
  service = f"WireGuardTunnel${peer}"
  if sc("query", service).returncode != SERVICE_MISSING:
    subprocess.run([WIREGUARD, "/uninstalltunnelservice", peer], check=True)
    # Removal is asynchronous; installing over a service marked for deletion fails.
    deadline = time.monotonic() + 30
    while sc("query", service).returncode != SERVICE_MISSING and time.monotonic() < deadline:
      time.sleep(1)
  subprocess.run([WIREGUARD, "/installtunnelservice", conf], check=True)
  sc("failure", service, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/60000")
  log.info("installed tunnel service %s from %s", service, conf)


def apply_release(peer: str, tag: str, conf: Path, state: dict[str, str]) -> bool:
  """Fetch *tag*'s conf for *peer*, fill in the key, and reinstall if it changed; True when it did."""
  try:
    text = http_get(HUB_CONF_URL.format(tag=tag, peer=peer))
  except urllib.error.HTTPError as e:
    if e.code != 404:  # noqa: PLR2004
      raise
    # Recorded first so the alert fires once per release, not every run.
    state["hub_tag"] = tag
    STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
    raise RuntimeError(f"wireguard-hub {tag} has no {peer}.conf: this peer is not enrolled") from None
  if text.count(KEY_PLACEHOLDER) != 1:
    raise RuntimeError(f"{peer}.conf from {tag} does not hold exactly one {KEY_PLACEHOLDER}")
  key = (HOME / f"{peer}.key").read_text(encoding="utf-8").strip()
  filled = text.replace(KEY_PLACEHOLDER, key)
  changed = not conf.exists() or conf.read_text(encoding="utf-8") != filled
  if changed:
    conf.write_text(filled, encoding="utf-8")
    install_tunnel(peer, conf)
  state["hub_tag"] = tag
  log.info("hub %s applied (%s)", tag, "conf changed, tunnel reinstalled" if changed else "conf unchanged")
  return changed


def ensure_running(peer: str, conf: Path) -> bool:
  """Install the tunnel service if missing and start it if stopped; True when it had to."""
  service = f"WireGuardTunnel${peer}"
  query = sc("query", service)
  if query.returncode == SERVICE_MISSING:
    if not conf.exists():
      raise RuntimeError(f"tunnel service {service} is missing and no conf has been fetched yet")
    install_tunnel(peer, conf)
    return True
  if "RUNNING" not in query.stdout:
    sc("start", service)
    log.warning("tunnel service %s was not running; started it", service)
    return True
  return False


def handshake_fresh(peer: str, *, settle: bool) -> bool:
  """Whether the tunnel's latest handshake is younger than `STALE_SECS`, waiting `SETTLE_SECS` if *settle*."""
  deadline = time.monotonic() + (SETTLE_SECS if settle else 0)
  while True:
    out = subprocess.run([WG, "show", peer, "latest-handshakes"], capture_output=True, text=True, check=False).stdout
    stamps = [int(f) for line in out.splitlines() if (f := line.rpartition("\t")[2]).isdigit()]
    if any(s and time.time() - s < STALE_SECS for s in stamps):
      return True
    if time.monotonic() >= deadline:
      return False
    time.sleep(5)


def ping(*, fresh: bool) -> None:
  """Report *fresh* to healthchecks.io; a no-op unless `ALERTS_HEALTHCHECK_PING_URL` or `PINGKEY` is set."""
  # Third party imports
  from aeth_ext.monitoring.heartbeat import send_heartbeat
  from pydantic import SecretStr

  url, key = os.environ.get("ALERTS_HEALTHCHECK_PING_URL", "").strip(), os.environ.get("PINGKEY", "").strip()
  if not (url or key):
    return
  slug = os.environ.get("HEARTBEAT_SLUG", "").strip() or f"wireguard-spoke-{os.environ['WG_PEER_NAME']}"
  send_heartbeat(None, ping_url=SecretStr(url) if url else None, pingkey=SecretStr(key) if key else None, slug=slug, failure=not fresh)


def required_python() -> str | None:
  """`3.N` when the newest wheel on the index requires a newer Python than this one, else None."""
  page = http_get(INDEX_URL)
  newest: tuple[tuple[int, ...], str] | None = None
  for m in re.finditer(r'data-requires-python="([^"]*)"[^>]*>wireguard_spoke_agent-([0-9][0-9.]*)-py3-none-any\.whl<', page):
    version = tuple(int(p) for p in m[2].strip(".").split("."))
    if newest is None or version > newest[0]:
      newest = (version, html.unescape(m[1]))
  floor = re.fullmatch(r">=\s*3\.(\d+)(\.\d+)?", newest[1].strip()) if newest else None
  return f"3.{floor[1]}" if floor and sys.version_info < (3, int(floor[1])) else None


def reconcile(state: dict[str, str]) -> None:
  """Re-render `run.cmd` and re-register the scheduled task when either differs from the package templates."""
  try:
    python = required_python()
  except OSError as e:
    log.warning("package index unreachable, keeping the current --python choice: %r", e)
    python = state.get("python") or None
  state["python"] = python or ""
  templates = files("wireguard_spoke_agent")
  run_cmd = templates.joinpath("run.cmd").read_text(encoding="utf-8").format(home=HOME, python_arg=f" --python {python}" if python else "")
  # cmd.exe wants CRLF; the package file's line endings depend on how it was checked out.
  run_cmd = "\r\n".join(run_cmd.splitlines()) + "\r\n"
  if not RUN_CMD.exists() or RUN_CMD.read_bytes() != run_cmd.encode("utf-8"):
    RUN_CMD.write_bytes(run_cmd.encode("utf-8"))
    log.info("rendered %s%s", RUN_CMD, f" (next upgrade moves to Python {python})" if python else "")
  task = templates.joinpath("task.xml").read_text(encoding="utf-8").format(home=HOME, run_cmd=RUN_CMD)
  digest = hashlib.sha256(task.encode("utf-8")).hexdigest()
  registered = subprocess.run(["schtasks.exe", "/Query", "/TN", TASK_NAME], capture_output=True, check=False).returncode == 0
  if not registered or state.get("task_sha256") != digest:
    TASK_XML.write_text(task, encoding="utf-16")  # schtasks /XML reads the encoding the declaration names
    subprocess.run(["schtasks.exe", "/Create", "/TN", TASK_NAME, "/XML", TASK_XML, "/F"], capture_output=True, check=True)
    state["task_sha256"] = digest
    log.info("registered scheduled task %s", TASK_NAME)


def run() -> bool:
  """One maintenance pass (module docstring, steps 2-5); returns True so the fatal wrapper's None marks failure."""
  peer = os.environ["WG_PEER_NAME"]
  conf = HOME / f"{peer}.conf"
  state: dict[str, str] = json.loads(STATE_FILE.read_text(encoding="utf-8")) if STATE_FILE.exists() else {}
  try:
    tag = http_get(HUB_VERSION_URL).strip()
  except OSError as e:
    log.warning("hub unreachable, skipping the release check: %r", e)
    tag = None
  changed = apply_release(peer, tag, conf, state) if tag and tag != state.get("hub_tag") else False
  restarted = ensure_running(peer, conf)
  fresh = handshake_fresh(peer, settle=changed or restarted)
  log.info("handshake %s", "fresh" if fresh else "stale")
  ping(fresh=fresh)
  reconcile(state)
  STATE_FILE.write_text(json.dumps(state, indent=2), encoding="utf-8")
  return True


def main() -> None:
  """Entry point: `wireguard-spoke-agent` for a scheduled run, `wireguard-spoke-agent install` once at setup."""
  LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
  logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    handlers=[RotatingFileHandler(LOG_FILE, maxBytes=1024**2, backupCount=3, encoding="utf-8"), logging.StreamHandler()],
  )
  load_settings()
  # Third party imports
  from aeth_ext.errors import handle_fatal_exc_sync

  if sys.argv[1:] == ["install"]:
    # Interactive, from the spoke's installer: let exceptions surface on its console.
    run()
    return
  if sys.argv[1:]:
    sys.exit("usage: wireguard-spoke-agent [install]")
  sys.exit(0 if handle_fatal_exc_sync(run)() else 1)


if __name__ == "__main__":
  main()

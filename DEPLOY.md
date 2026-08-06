# Deployment

`netaudit` is a command-line tool, not a service: there is no daemon to supervise, no
port to open and no systemd unit to write. Deploying it means three things.

1. Install the package and its locked dependencies.
2. Provision the inventory file, which is never carried by the repository.
3. Confirm the host can reach the management interfaces of the switches.

Step 3 is the one that actually fails. The rest is mechanical.

## Prerequisites on the target host

Only `uv`:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
```

It is a single static binary and pulls in nothing else. A system Python is *not*
required — uv provisions the interpreter pinned in `.python-version` itself, which is
the point: an operating system upgrade that replaces the system Python cannot break
the installation.

## Standard procedure

```bash
git clone <repository-url> /opt/netaudit
cd /opt/netaudit

uv python install "$(cat .python-version)"
uv sync --frozen --no-dev

ln -sf /opt/netaudit/.venv/bin/netaudit /usr/local/bin/netaudit
```

`--frozen` installs exactly what `uv.lock` records and refuses to re-resolve anything.
**Never omit it on a server.** Without it uv may resolve fresh versions, which is how
`paramiko` 4.x — the release that breaks key authentication against the Mocana SSH
stack on Aruba/HP switches — would silently reappear.

`--no-dev` skips pytest and ruff, which have no reason to exist on a client host.

The symlink works because the generated entry point carries an absolute shebang
pointing at `/opt/netaudit/.venv/bin/python`. For the same reason the virtualenv
**cannot be moved after creation**; relocating `/opt/netaudit` means re-running
`uv sync --frozen --no-dev`.

If the repository is not reachable from the target, replace the clone with:

```bash
rsync -a --exclude .venv --exclude .git ./ root@server:/opt/netaudit/
```

## Provisioning the inventory

`switches.yaml` holds credentials and is listed in `.gitignore`, so it arrives with
neither the clone nor the rsync above. It is always a separate, deliberate step:

```bash
scp switches.yaml root@server:/root/.config/netaudit/switches.yaml
ssh root@server 'chmod 600 /root/.config/netaudit/switches.yaml'
```

`~/.config/netaudit/switches.yaml` is the last entry in the lookup chain, so it
resolves from any working directory — unlike `./switches.yaml`, which depends on where
the command happens to be run. For a file shared between users, put it somewhere
explicit instead:

```bash
export NETAUDIT_SWITCHES_FILE=/etc/netaudit/switches.yaml
```

Prefer SSH key authentication where the switches accept it: omit the `password` field
and no secret is stored on the host at all. Note that an unattended run — cron, a
timer — has no SSH agent in its session, so it needs either passwords in the file
(mode 600) or a dedicated key referenced from `~/.ssh/config`.

## Verification

```bash
netaudit --version
nc -vz <switch-ip> 22                      # reachability; ICMP is usually blocked
netaudit --switch <name> vlans             # first real call, read-only
```

A failure at the third step but not the second is a credentials or `device_type`
problem, not a networking one.

## Updates

```bash
cd /opt/netaudit
git pull
uv sync --frozen --no-dev
```

`switches.yaml` is never touched by an update.

## Variants

**Air-gapped target.** Build the bundle on a connected machine, then carry it over:

```bash
uv build --wheel                                   # dist/netaudit-*.whl
uv export --frozen --no-dev > requirements.txt     # lockfile in pip format
uv pip download -r requirements.txt -d vendor/
# on the target:
pip install --no-index --find-links vendor/ requirements.txt dist/netaudit-*.whl
```

This is the only legitimate use of a `requirements.txt` in this project: a generated
artifact, never a source of truth, never committed.

**Target where uv cannot be installed.** Fall back to a classic virtualenv built from
the exported lockfile. The dependency versions stay exact, but the interpreter becomes
the system one again — which means an OS upgrade can break it. Say so in the handover
notes.

```bash
uv export --frozen --no-dev > requirements.txt     # on your machine, then copy over
python3 -m venv /opt/netaudit/venv
/opt/netaudit/venv/bin/pip install -r requirements.txt
/opt/netaudit/venv/bin/pip install --no-deps /opt/netaudit
```

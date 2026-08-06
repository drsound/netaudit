# netaudit — Network Switch Diagnostic and Configuration Tool

`netaudit` is a robust, multi-vendor CLI tool designed to simplify everyday network switch operations, diagnostics, and inventory management. By leveraging `netmiko` and an intelligent Nmap XML database integration, it provides an expressive and safe way to query infrastructure, apply configuration changes, and analyze topology health.

---

## Key Features

- **Multi-Vendor Support**: Out-of-the-box support for Aruba, HP ProCurve, HP Comware, Fiberstore (FS), TP-Link JetStream, and Netgear switches via Netmiko adapters.
- **Deep Network Diagnostics**: Perform advanced STP analysis (Edge anomalies, Root Guard checks), interface level physical checks (Speed mismatches, SFP DDMI), and intelligent log auditing for flapping ports and correlated config changes.
- **Automated Rogue Device Detection**: Easily locate unmanaged hubs or rogue devices connected to non-edge ports using a single command.
- **Safe Configuration Modifications**: Write commands follow a strict Preview-Confirm-Execute-Verify workflow, preventing accidental network outages.
- **Nmap Database Integration**: Overlay live switch MAC address tables with deep Nmap scan data (IP resolving, OS fingerprinting, open services lists).
- **CI/CD & Export Ready**: Global standard CSV export capabilities and non-interactive `--yes` flags make `netaudit` ideal for scripting, documentation dumping, or integration with automation loops.

---

## Prerequisites & Installation

**Prerequisites:**
- [uv](https://docs.astral.sh/uv/) — `brew install uv`, or `curl -LsSf https://astral.sh/uv/install.sh | sh`
- Network access to the management interfaces of your networking equipment.

You do not need to install Python yourself: uv provisions the interpreter pinned in
`.python-version`, independently of whatever Python the operating system ships.

**Installation:**
```bash
git clone https://github.com/your-username/netaudit.git
cd netaudit

uv sync
```

`uv sync` reads `pyproject.toml`, resolves against the committed `uv.lock`, creates
`.venv/` and installs the project into it — no virtualenv to activate by hand. Run
anything through `uv run`:

```bash
uv run netaudit --switch core_switch vlans
```

To get a bare `netaudit` command on your `PATH` instead, symlink the entry point the
install generated (its shebang points at the venv interpreter, so it works from any
directory):

```bash
ln -sf "$PWD/.venv/bin/netaudit" /usr/local/bin/netaudit
```

For deployment on a server, see [DEPLOY.md](DEPLOY.md).

> **Do not install the dependencies by hand.** `paramiko` must stay on the 3.x line:
> version 4.0 removed the SHA-1 `ssh-rsa` algorithm that the Mocana SSH stack on
> Aruba/HP switches requires for key authentication. `pyproject.toml` pins it and
> `uv.lock` freezes it at an exact version; a manual `pip install netmiko paramiko`
> does neither. See [Troubleshooting](#troubleshooting).

---

## Configuration

Switches are defined in `switches.yaml`. You can copy the template to get started:
```bash
cp switches.yaml.example switches.yaml
```

**Example `switches.yaml` entries:**
```yaml
switches:
  core_switch:
    host: 192.168.1.100
    user: admin
    password: mySecretPassword
    device_type: aruba_osswitch   
    expected_root_mac: "00:11:22:33:44:55"
```

`host`, `user`, `password` and `device_type` configure the SSH connection. Any other
key (`model`, `location`, `expected_root_mac`, …) is inventory metadata: it is kept
alongside the connection and read by the commands that need it — `stp detail` uses
`expected_root_mac` to verify the active root bridge.

### SSH Public Key Authentication
`netaudit` fully supports SSH public key authentication. If you omit the `password` field from your `switches.yaml` definition (or the `--password` CLI argument), the tool will automatically attempt to authenticate using your standard SSH keys (e.g., `~/.ssh/id_rsa` or `ssh-agent`).

Alternatively, if you prefer not to use the YAML inventory, you can pass connection arguments directly via CLI:
```bash
netaudit --host 192.168.1.100 --user admin --password secret vlans
netaudit --host 192.168.1.100 --user admin vlans  # Falls back to SSH Key Auth
```

### Custom Inventory Path
The inventory file is resolved in this order, first hit wins:

1. `--switches-file <path>`
2. `$NETAUDIT_SWITCHES_FILE`
3. `./switches.yaml` in the current working directory
4. `~/.config/netaudit/switches.yaml`

```bash
# Using the environment variable
export NETAUDIT_SWITCHES_FILE="/path/to/my_switches.yaml"
netaudit --switch core_switch diagnose

# Using the command line option
netaudit --switches-file "/custom/path/switches.yaml" --switch core_switch vlans
```

---

## Usage Guide

`netaudit` provides various command families tailored for both quick checks and extensive infrastructure refactoring.

### 1. Read Operations & Diagnostics

```bash
# Full diagnosis: runs all read commands and saves a timestamped report
netaudit --switch core_switch diagnose

# Display raw running configuration
netaudit --switch core_switch config

# General read queries
netaudit --switch core_switch vlans
netaudit --switch core_switch vlan 2
netaudit --switch core_switch ports
netaudit --switch core_switch port-names       # Fetch all interface descriptions
netaudit --switch core_switch neighbors        # Map LLDP topology

# Execute arbitrary "show" commands
netaudit --switch core_switch query "show ip routing"
```

**Advanced Diagnostics:**
```bash
# Spanning Tree analysis (TC events, blocking ports, topology root)
netaudit --switch core_switch stp check

# Deep STP structural analysis (Root Guard, TCN Guard, Edge vs OperEdge mismatches)
netaudit --switch core_switch stp detail

# Detect anomalies in physical media (speed mismatches, MDIX, Transceiver health)
netaudit --switch core_switch physical-check

# Audit log streams over time for loops, flapping events, and topology changes
netaudit --switch core_switch log-audit
```

### 2. Modifying Configurations

Remember: Configuration saving (`write memory`) is always a separate, explicit action to prevent accidental NVRAM pollution. Every write command prints a safe preview and asks for confirmation by default.

```bash
# VLAN manipulation
netaudit --switch core_switch vlan create 99 "GUEST_NETWORK"
netaudit --switch core_switch vlan rename 99 "IoT_NETWORK"
netaudit --switch core_switch vlan delete 99   # Will warn if active ports exist

# Switchport manipulation
netaudit --switch core_switch port access 1/3 10
netaudit --switch core_switch port tag 2/A1 100
netaudit --switch core_switch port untag 2/A1 100
netaudit --switch core_switch port set-name 1/2 "Aruba_AP_Office"
netaudit --switch core_switch port set-name 1/2 "" # Clears description

# Save running-config to startup-config
netaudit --switch core_switch save
```

### 3. Nmap Database Integration

By generating standard Nmap XML outputs (`nmap -oX nmap-output.xml`), `netaudit` can enrich layer 2 data with layer 3/4/7 information, helping network operators trace specific physical ports to precise OS/Service assets.

> Ensure the XML file is named `nmap-output.xml` in your working directory, or set the path via `--nmap-db <path>` or the `NETAUDIT_NMAP_DB` env variable.

**Recommended Nmap Scan Command:**
To get the most out of `netaudit`, use a scan that includes OS detection and service versioning:
```bash
nmap -sS -sU -p T:21,22,23,80,135,139,443,445,3389,5000,8080,8443,U:137,161,5353 -O -sV --version-light --script=nbstat,smb-os-discovery,snmp-sysdescr,dns-service-discovery -T4 -oX nmap-output.xml 192.168.1.0/24
```

```bash
# List all active layer 3 hosts loaded in the DB
netaudit inventory

# Filter assets by OS or open services
netaudit inventory --os win
netaudit inventory --service ssh

# MAC table tracking and rogue switch detection
netaudit --switch core_switch port find 10.168.0.3        # Find physical port by IP
netaudit --switch core_switch port find DESKTOP-PC        # Find physical port by name
netaudit --switch core_switch port find aa:bb:cc:dd:ee:ff # Find physical port by MAC
netaudit --switch core_switch port find --rogue           # Find multiple MACs on Edge ports automatically

# See a live MAC table enriched with DNS names, Vendor OUI, and OS fingerprint from the Nmap scan
netaudit --switch core_switch macs
```

### 4. Data Export (CSV) & Open Services Display

`netaudit` can effortlessly parse convoluted command outputs into machine-readable comma-separated datasets.

To export pure CSV data, pass the `--csv` flag **before** any subcommand. This silences connection logs allowing standard bash pipes:
```bash
netaudit --switch core_switch --csv ports > interface_status.csv
netaudit --switch core_switch --csv port-names > cable_docs.csv
netaudit --switch core_switch --csv neighbors > lldp_topology.csv
netaudit --switch core_switch --csv port find --rogue > rogue_report.csv
```

To extract full port and service vectors from Nmap, append `--services` to inventory or MAC commands:
```bash
# Print formatted columns including active TCP/UDP ports
netaudit inventory --services

# Export a highly-detailed enriched MAC table complete with open service arrays directly to CSV
netaudit --switch core_switch --csv macs --services > asset_matrix.csv
```

### 5. Automation (`--yes`)

Bypass interactive confirmation prompts programmatically using the non-interactive `--yes` flag.

```bash
netaudit --switch core_switch --yes vlan create 99 TEST
netaudit --switch core_switch --yes port set-name 2/24 "ESXi-Server"
netaudit --switch core_switch --yes save
```

---

## Project Structure

```text
netaudit/
├── pyproject.toml         # Dependencies, entry point, lint and test config
├── switches.yaml          # Environment inventory (user-defined, git-ignored)
├── switches.yaml.example  # Annotated inventory template
├── netaudit/
│   ├── cli.py             # Argument parsing and dispatch
│   ├── config.py          # switches.yaml and nmap DB resolution
│   ├── switch.py          # Netmiko connection wrapper (SSH agent + password fallback)
│   ├── diagnostics.py     # Read operations, log processors, output parsers
│   ├── modifications.py   # Guardrailed write operations
│   ├── nmap_parser.py     # Nmap XML host correlation
│   ├── formatting.py      # Shared table/CSV rendering and MAC enrichment
│   └── commands/          # One module per command family, each owning its
│       ├── system.py      #   handler, subparser and argument validation
│       ├── vlan.py
│       ├── stp.py
│       ├── port.py
│       ├── mac.py
│       ├── topology.py
│       └── inventory.py
└── tests/
```

Adding a command means adding a `Command(...)` entry to the relevant module in
`src/netaudit/commands/`; `cli.py` builds the parser by walking the registry, so no
central list needs updating.

## Development

```bash
uv sync                  # environment + dev dependencies, from uv.lock
uv run pytest            # test suite
uv run ruff check .      # lint
```

Dependency changes go through uv so that `pyproject.toml` and `uv.lock` stay in step:

```bash
uv add <package>         # runtime dependency
uv add --dev <package>   # development-only dependency
uv lock --upgrade        # refresh the lockfile deliberately
```

Never hand-edit `uv.lock`, and commit it with the change that caused it.

The package lives under `src/`, so the copy under test is always the installed one —
imports cannot silently succeed just because the repository root happens to be the
working directory.

## Troubleshooting

**`An RSA key was specified, but no RSA pubkey algorithms are configured!`**
You are on paramiko 4.x. Aruba/HP switches run Mocana SSH 6.3, which only signs
user authentication with the legacy SHA-1 `ssh-rsa` algorithm; paramiko 4.0 removed
it. Re-sync with `uv sync` so the exact version recorded in `uv.lock` is restored.

**`No route to host` / `TCP connection to device failed` on macOS, but `ssh` works**
On macOS 15+ Local Network access is granted to the *app* that owns the terminal
session, not to the interpreter. From a terminal app without that permission every
non-Apple-signed binary (Homebrew python, ncat, …) fails, while Apple-signed ones
(`/usr/bin/nc`, `ssh`, `/usr/bin/python3`) keep working — which makes it look like a
routing problem. An app only appears under *System Settings → Privacy & Security →
Local Network* if it declares `NSLocalNetworkUsageDescription` in its `Info.plist`;
apps that do not are never prompted and cannot be granted access. Run `netaudit`
from Terminal.app or iTerm2 if the LAN is unreachable from your usual terminal.

## Contributing

Contributions to `netaudit` are highly appreciated. Feel free to open issues or pull requests on GitHub for bug fixes or features, especially adding support for new switch models and parsing modules!

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

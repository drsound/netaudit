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
- Python 3.8+
- Network access to the management interfaces of your networking equipment.

**Installation:**
```bash
# Clone the repository
git clone https://github.com/your-username/netaudit.git
cd netaudit

# Install required Python dependencies
pip install netmiko pyyaml
```

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

### SSH Public Key Authentication
`netaudit` fully supports SSH public key authentication. If you omit the `password` field from your `switches.yaml` definition (or the `--password` CLI argument), the tool will automatically attempt to authenticate using your standard SSH keys (e.g., `~/.ssh/id_rsa` or `ssh-agent`).

Alternatively, if you prefer not to use the YAML inventory, you can pass connection arguments directly via CLI:
```bash
python3 netaudit.py --host 192.168.1.100 --user admin --password secret vlans
python3 netaudit.py --host 192.168.1.100 --user admin vlans  # Falls back to SSH Key Auth
```

---

## Usage Guide

`netaudit` provides various command families tailored for both quick checks and extensive infrastructure refactoring.

### 1. Read Operations & Diagnostics

```bash
# Full diagnosis: runs all read commands and saves a timestamped report
python3 netaudit.py --switch core_switch diagnose

# Display raw running configuration
python3 netaudit.py --switch core_switch config

# General read queries
python3 netaudit.py --switch core_switch vlans
python3 netaudit.py --switch core_switch vlan 2
python3 netaudit.py --switch core_switch ports
python3 netaudit.py --switch core_switch port-names       # Fetch all interface descriptions
python3 netaudit.py --switch core_switch neighbors        # Map LLDP topology

# Execute arbitrary "show" commands
python3 netaudit.py --switch core_switch query "show ip routing"
```

**Advanced Diagnostics:**
```bash
# Spanning Tree analysis (TC events, blocking ports, topology root)
python3 netaudit.py --switch core_switch stp check

# Deep STP structural analysis (Root Guard, TCN Guard, Edge vs OperEdge mismatches)
python3 netaudit.py --switch core_switch stp detail

# Detect anomalies in physical media (speed mismatches, MDIX, Transceiver health)
python3 netaudit.py --switch core_switch physical-check

# Audit log streams over time for loops, flapping events, and topology changes
python3 netaudit.py --switch core_switch log-audit
```

### 2. Modifying Configurations

Remember: Configuration saving (`write memory`) is always a separate, explicit action to prevent accidental NVRAM pollution. Every write command prints a safe preview and asks for confirmation by default.

```bash
# VLAN manipulation
python3 netaudit.py --switch core_switch vlan create 99 "GUEST_NETWORK"
python3 netaudit.py --switch core_switch vlan rename 99 "IoT_NETWORK"
python3 netaudit.py --switch core_switch vlan delete 99   # Will warn if active ports exist

# Switchport manipulation
python3 netaudit.py --switch core_switch port access 1/3 10
python3 netaudit.py --switch core_switch port tag 2/A1 100
python3 netaudit.py --switch core_switch port untag 2/A1 100
python3 netaudit.py --switch core_switch port set-name 1/2 "Aruba_AP_Office"
python3 netaudit.py --switch core_switch port set-name 1/2 "" # Clears description

# Save running-config to startup-config
python3 netaudit.py --switch core_switch save
```

### 3. Nmap Database Integration

By generating standard Nmap XML outputs (`nmap -oX nmap-output.xml`), `netaudit` can enrich layer 2 data with layer 3/4/7 information, helping network operators trace specific physical ports to precise OS/Service assets.

> Ensure the XML file is named `nmap-output.xml` in your working directory, or set the path via `--nmap-db <path>` or the `NETAUDIT_NMAP_DB` env variable.

```bash
# List all active layer 3 hosts loaded in the DB
python3 netaudit.py inventory

# Filter assets by OS or open services
python3 netaudit.py inventory --os win
python3 netaudit.py inventory --service ssh

# MAC table tracking and rogue switch detection
python3 netaudit.py --switch core_switch port find 10.168.0.3        # Find physical port by IP
python3 netaudit.py --switch core_switch port find DESKTOP-PC        # Find physical port by name
python3 netaudit.py --switch core_switch port find aa:bb:cc:dd:ee:ff # Find physical port by MAC
python3 netaudit.py --switch core_switch port find --rogue           # Find multiple MACs on Edge ports automatically

# See a live MAC table enriched with DNS names, Vendor OUI, and OS fingerprint from the Nmap scan
python3 netaudit.py --switch core_switch macs
```

### 4. Data Export (CSV) & Open Services Display

`netaudit` can effortlessly parse convoluted command outputs into machine-readable comma-separated datasets.

To export pure CSV data, pass the `--csv` flag **before** any subcommand. This silences connection logs allowing standard bash pipes:
```bash
python3 netaudit.py --switch core_switch --csv ports > interface_status.csv
python3 netaudit.py --switch core_switch --csv port-names > cable_docs.csv
python3 netaudit.py --switch core_switch --csv neighbors > lldp_topology.csv
python3 netaudit.py --switch core_switch --csv port find --rogue > rouge_reports.csv
```

To extract full port and service vectors from Nmap, append `--services` to inventory or MAC commands:
```bash
# Print formatted columns including active TCP/UDP ports
python3 netaudit.py inventory --services

# Export a highly-detailed enriched MAC table complete with open service arrays directly to CSV
python3 netaudit.py --switch core_switch --csv macs --services > asset_matrix.csv
```

### 5. Automation (`--yes`)

Bypass interactive confirmation prompts programmatically using the non-interactive `--yes` flag.

```bash
python3 netaudit.py --switch core_switch --yes vlan create 99 TEST
python3 netaudit.py --switch core_switch --yes port set-name 2/24 "ESXi-Server"
python3 netaudit.py --switch core_switch --yes save
```

---

## File Structure

```text
netaudit/
├── netaudit.py        # Core CLI Entry Point and Argument Parser Layer
├── switches.yaml      # Environment Inventory file (User-defined)
└── lib/
    ├── switch.py          # Abstracted Netmiko execution handler
    ├── diagnostics.py     # Log processors, syntax parsers, and read operations
    ├── modifications.py   # Guardrailed write operations
    └── nmap_parser.py     # XML processing class for host correlation logic
```

## Contributing

Contributions to `netaudit` are highly appreciated. Feel free to open issues or pull requests on GitHub for bug fixes or features, especially adding support for new switch models and parsing modules!

## License

This project is licensed under the GNU General Public License v3.0 - see the LICENSE file for details.

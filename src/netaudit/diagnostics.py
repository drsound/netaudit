import re
from datetime import datetime

from netaudit.nmap_parser import normalize_mac


def get_running_config(sw):
    return sw.run('show running-config', timeout=120)


def get_vlans(sw):
    return sw.run('show vlan')


def get_vlan(sw, vlan_id):
    return sw.run(f'show vlan {vlan_id}')


def get_spanning_tree(sw):
    return sw.run('show spanning-tree')


def get_interface_brief(sw, format_csv=False):
    output = sw.run('show interface brief')
    if not format_csv:
        return output

    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(['Port', 'Type', 'Enabled', 'Status', 'Mode', 'MDI'])

    # Format: 1/1  100/1000T  | No  Yes  Up   100FDx  MDI  off  0
    for line in output.splitlines():
        # Using a more robust regex to split columns around the pipe
        m = re.match(
            r'^\s*([\w/]+)\s+([\w/]+)\s+\|\s+(Yes|No)\s+(Yes|No)\s+(Up|Down|Drop)'
            r'\s+([0-9A-Za-z]+)\s+([0-9A-Za-z\-]+)\s+', line)
        if m:
            port, ptype, alert, enabled, status, mode, mdi = m.groups()
            writer.writerow([port, ptype, enabled, status, mode, mdi])

    return out.getvalue().strip()


def get_port_names(sw, port=None, format_csv=False):
    output = sw.run('show name')

    if format_csv:
        import csv
        import io
        out = io.StringIO()
        writer = csv.writer(out)
        writer.writerow(['Port', 'Type', 'Name/Comment'])

        for line in output.splitlines():
            # Format:  1/1    100/1000T  Server-01
            m = re.match(r'^\s*([\w/]+)\s+([\w/]+)\s+(.*)', line)
            if m and not m.group(1).isalpha(): # skip header lines like 'Port'
                p, t, n = m.groups()
                if port and p != port:
                    continue
                writer.writerow([p, t, n.strip()])
        return out.getvalue().strip()

    if port is None:
        return output
    # Filter: return only the header lines + the matching port line
    lines = output.splitlines()
    result = []
    for line in lines:
        # Header lines (non-data) or the matching port
        if not re.match(r'\s+\d', line) and not re.match(r'\s+\w+/\w', line):
            result.append(line)
        elif re.match(rf'\s+{re.escape(port)}\s', line):
            result.append(line)
    return '\n'.join(result)


def get_lldp_neighbors(sw, format_csv=False):
    output = sw.run('show lldp info remote-device')
    if not format_csv:
        return output

    import csv
    import io
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(['Local Port', 'Chassis ID', 'Port ID', 'System Name'])

    # Format:
    #   LocalPort | ChassisId          PortId             PortDescr SysName
    #   --------- + ------------------ ------------------ --------- ------------------
    #   1/4       | ec0273-02c200      48                 48        13.29_R3_ARUBA
    in_data = False
    chassis_idx = portid_idx = portdescr_idx = sysname_idx = -1

    for line in output.splitlines():
        if not in_data:
            if 'ChassisId' in line and 'PortId' in line:
                chassis_idx = line.find('ChassisId')
                portid_idx = line.find('PortId')
                portdescr_idx = line.find('PortDescr')
                sysname_idx = line.find('SysName')
            elif re.match(r'^\s*-+\s*\+\s*-+', line):
                in_data = True
            continue

        if in_data and '|' in line:
            parts = line.split('|', 1)
            local_port = parts[0].strip()

            # Missing local_port or end of output
            if not local_port:
                continue

            if chassis_idx > 0 and portid_idx > 0 and sysname_idx > 0:
                chassis = line[chassis_idx:portid_idx].strip()

                end_port_id = portdescr_idx if portdescr_idx > 0 else sysname_idx
                port_id = line[portid_idx:end_port_id].strip()

                sys_name = line[sysname_idx:].strip()
                writer.writerow([local_port, chassis, port_id, sys_name])

    return out.getvalue().strip()


def get_mac_table(sw, port=None, vlan=None):
    cmd = 'show mac-address'
    if port:
        cmd += f' {port}'
    if vlan:
        cmd += f' vlan {vlan}'
    return sw.run(cmd)


def get_logs(sw):
    return sw.run('show log -r')


def check_stp_health(sw):
    output = get_spanning_tree(sw)
    warnings = []
    info = []

    # Check for STP being disabled
    if re.search(r'STP Enabled\s*:\s*No', output, re.IGNORECASE):
        warnings.append("WARNING: STP is disabled on this switch!")

    # Extract root bridge info
    root_mac = re.search(r'CST Root MAC Address\s*:\s*([\w\-:]+)', output)
    root_pri = re.search(r'CST Root Priority\s*:\s*(\d+)', output)
    if root_mac:
        info.append(f"Root Bridge MAC: {root_mac.group(1)}")
    if root_pri:
        info.append(f"Root Bridge Priority: {root_pri.group(1)}")

    # Check if this switch is the root
    bridge_mac = re.search(r'(?:Switch|Bridge) MAC Address\s*:\s*([\w\-:]+)', output)
    if root_mac and bridge_mac and root_mac.group(1) == bridge_mac.group(1):
        info.append("This switch IS the Root Bridge")

    # Look for topology change counters. The switch groups thousands
    # ("530,618"), so a bare \d+ stopped at the first comma and reported 530.
    tc_count = re.search(r'(?:Topology Change Count|TCN Count)\s*[:\s]+([\d,]+)',
                         output, re.IGNORECASE)
    if tc_count:
        count = int(tc_count.group(1).replace(',', ''))
        if count > 100:
            warnings.append(f"WARNING: High Topology Change Count: {count} (possible STP loop)")
        else:
            info.append(f"Topology Change Count: {count}")

    # Scan port states
    blocking_ports = []
    discarding_ports = []
    # Match lines like: A1  100Mbit  200000  128  Blocking  Alternate
    for line in output.splitlines():
        # Look for port state columns
        m = re.match(r'\s*([\w/]+)\s+\S+\s+\d+\s+\d+\s+(Blocking|Discarding|Disabled)\s+', line)
        if m:
            port_name = m.group(1)
            state = m.group(2)
            if state == 'Blocking':
                blocking_ports.append(port_name)
            elif state == 'Discarding':
                discarding_ports.append(port_name)

    if blocking_ports:
        info.append(f"Ports in Blocking: {', '.join(blocking_ports)}")
    if discarding_ports:
        warnings.append(f"Ports in Discarding (non-forwarding): {', '.join(discarding_ports)}")

    result = []
    if warnings:
        result.append("=== STP WARNINGS ===")
        result.extend(warnings)
        result.append("")
    if info:
        result.append("=== STP INFO ===")
        result.extend(info)
        result.append("")
    result.append("=== FULL OUTPUT ===")
    result.append(output)

    return '\n'.join(result)


#: Per-port Yes/No flags parsed out of "show spanning-tree detail",
#: mapped from the key used internally to the label printed by the switch.
_STP_PORT_FLAGS = {
    'admin_edge': 'AdminEdgePort',
    'oper_edge': 'OperEdgePort',
    'root_guard': 'Root Guard',
    'tcn_guard': 'TCN Guard',
    'loop_guard': 'Loop Guard',
    'bpdu_protect': 'BPDU Protection',
    'bpdu_filter': 'BPDU Filtering',
    'pvst_protect': 'PVST Protection',
    'pvst_filter': 'PVST Filtering',
}

#: The guards worth calling out per port, in the order they are reported.
_STP_GUARDS = ('root_guard', 'tcn_guard', 'loop_guard', 'bpdu_protect',
               'bpdu_filter', 'pvst_protect', 'pvst_filter')

#: Labels are matched with all whitespace removed. Firmware revisions disagree
#: on whether the label reads "RootGuard" or "Root Guard", and the compact
#: spelling this table used to hold matched nothing on any switch tested — so
#: four of the six flags were silently never parsed.
_STP_FLAG_BY_LABEL = {re.sub(r'\s+', '', label).lower(): key
                      for key, label in _STP_PORT_FLAGS.items()}

#: "Label : Value" line inside a port block.
_STP_KV_RE = re.compile(r'\s*([A-Za-z][A-Za-z0-9 /_-]*?)\s*:\s*(\S+)')


def get_edge_ports(sw):
    """Return the set of ports currently operating as STP edge ports.

    An edge port is expected to face a single end device, which is what makes a
    multi-MAC edge port a rogue-switch candidate.
    """
    output = sw.run('show spanning-tree detail')
    edge_ports = set()
    current_port = None
    for line in output.splitlines():
        m_port = re.match(r'^\s*Port\s*:\s*([\w/]+)', line)
        if m_port:
            current_port = m_port.group(1)
        elif current_port and re.search(r'OperEdgePort\s*:\s*Yes', line, re.IGNORECASE):
            edge_ports.add(current_port)
    return edge_ports


def get_stp_detail(sw, expected_root_mac=None):
    """Deep STP analysis parsing per-port details and root bridge MAC."""
    output = sw.run('show spanning-tree detail')
    summary_output = sw.run('show spanning-tree')

    warnings = []
    info = []

    # Global checks from summary output
    if re.search(r'STP Enabled\s*:\s*No', summary_output, re.IGNORECASE):
        warnings.append("CRITICAL: STP is disabled on this switch!")

    root_mac = re.search(r'CST Root MAC Address\s*:\s*([\w\-:]+)', summary_output)
    if root_mac:
        current_root = root_mac.group(1)
        if expected_root_mac:
            # Compare on the normalized form: the switch prints the Aruba
            # xxxxxx-xxxxxx notation while switches.yaml is documented with the
            # colon form, so a raw string compare never matched and every run
            # reported a bogus root-bridge mismatch.
            expected_norm = normalize_mac(expected_root_mac)
            if expected_norm is None:
                warnings.append(f"WARNING: expected_root_mac ({expected_root_mac}) is not a valid "
                                f"MAC address; skipping the root bridge check.")
            elif normalize_mac(current_root) != expected_norm:
                warnings.append(f"WARNING: CST Root MAC ({current_root}) does NOT match "
                                f"the expected root bridge ({expected_root_mac})!")
            else:
                info.append(f"CST Root MAC ({current_root}) matches the expected root bridge.")
        else:
            # Fallback: check if switch itself is root
            bridge_mac = re.search(r'(?:Switch|Bridge) MAC Address\s*:\s*([\w\-:]+)', summary_output)
            if not bridge_mac:
                info.append(f"CST Root MAC: {current_root} (switch MAC not reported; "
                            f"cannot tell whether this switch is the root)")
            elif normalize_mac(current_root) != normalize_mac(bridge_mac.group(1)):
                warnings.append(f"Notice: Switch is not root. CST Root MAC: {current_root}")
            else:
                info.append("This switch IS the Root Bridge")

    # Parse port-level detail
    port_data = {}
    current_port = None

    for line in output.splitlines():
        # Match port header: " Port: 1/1"
        m_port = re.match(r'^\s*Port\s*:\s*([\w/]+)', line)
        if m_port:
            current_port = m_port.group(1)
            port_data[current_port] = {}
            continue

        if not current_port:
            continue

        # Extract boolean/status values
        m_kv = _STP_KV_RE.match(line)
        if m_kv:
            key = _STP_FLAG_BY_LABEL.get(re.sub(r'\s+', '', m_kv.group(1)).lower())
            value = m_kv.group(2).capitalize()
            if key and value in ('Yes', 'No'):
                port_data[current_port][key] = value

    # Analyze parsed port data
    for port, data in port_data.items():
        # Edge port receiving BPDUs
        if data.get('admin_edge') == 'Yes' and data.get('oper_edge') == 'No':
            warnings.append(f"Port {port}: Configured as Edge (Admin) but operating as "
                            f"Non-Edge (BPDUs received!)")

        active_guards = [_STP_PORT_FLAGS[guard] for guard in _STP_GUARDS
                         if data.get(guard) == 'Yes']

        if active_guards:
            info.append(f"Port {port} active guards: {', '.join(active_guards)}")

    result = []
    if warnings:
        result.append("=== STP DETAIL WARNINGS ===")
        result.extend(warnings)
        result.append("")
    if info:
        result.append("=== STP DETAIL INFO ===")
        result.extend(info)
        result.append("")
    if not warnings and not info:
        result.append("No active guards or alerts found in detailed analysis.")

    return '\n'.join(result)


#: DDM alarm thresholds. Rx floor is the receive sensitivity shared by the
#: 1000SX / 10GBASE-SR optics these switches carry; below it a link is running
#: on no optical margin and is about to start erroring. Temperature and supply
#: voltage are the SFP MSA operating limits.
SFP_RX_LOW_DBM = -17.0
SFP_TEMP_HIGH_C = 70.0
SFP_VOLTAGE_RANGE = (3.0, 3.6)

#: "Transceiver in 1/21" starts a block; the metrics follow as "Label : value".
_SFP_BLOCK_RE = re.compile(r'^\s*Transceiver in (\S+)', re.IGNORECASE)
_SFP_KV_RE = re.compile(r'^\s*([A-Za-z][A-Za-z ]*?)\s*:\s*(.+?)\s*$')

#: Explicit, non-default port settings. running-config records only what was
#: configured away from the default, so a hit here IS a pinned setting.
_PINNED_SETTING_RE = re.compile(r'^\s*(speed-duplex|mdix-mode)\s+(\S+)', re.IGNORECASE)
_CONFIG_INTERFACE_RE = re.compile(r'^\s*interface\s+(\S+)', re.IGNORECASE)


def _parse_transceivers(output):
    """Parse "show interfaces transceiver detail" into {port: {label: value}}.

    The switches emit a multi-line block per transceiver ("Transceiver in 1/21",
    then an indented "Status" section). The previous parser expected a single
    tabular line per SFP, a layout this hardware never produces, so it always
    concluded there were no diagnostics at all.
    """
    blocks = {}
    current = None
    for line in output.splitlines():
        m_block = _SFP_BLOCK_RE.match(line)
        if m_block:
            current = m_block.group(1)
            blocks[current] = {}
            continue
        if current is None:
            continue
        m_kv = _SFP_KV_RE.match(line)
        if m_kv:
            blocks[current][m_kv.group(1).strip().lower()] = m_kv.group(2).strip()
    return blocks


def _sfp_number(raw, unit):
    """Pull the leading number off a DDM value such as "30.562C" or "0.33mW, -4.78dBm"."""
    if not raw:
        return None
    m = re.search(rf'(-?\d+(?:\.\d+)?)\s*{unit}', raw)
    return float(m.group(1)) if m else None


def _check_transceivers(output, warnings, info):
    if 'Invalid input' in output or 'does not support' in output:
        info.append("SFP DDM Diagnostics (show interfaces transceiver detail) "
                    "not supported on this switch.")
        return

    blocks = _parse_transceivers(output)
    if not blocks:
        info.append("No active SFP physical diagnostics found.")
        return

    for port, data in sorted(blocks.items()):
        temp = _sfp_number(data.get('temperature'), 'C')
        volt = _sfp_number(data.get('voltage'), 'V')
        tx_dbm = _sfp_number(data.get('tx power'), 'dBm')
        rx_dbm = _sfp_number(data.get('rx power'), 'dBm')

        if temp is None and volt is None and rx_dbm is None:
            # A transceiver without DOM support still gets a block.
            info.append(f"SFP on {port}: {data.get('type', 'unknown type')} "
                        f"({data.get('model', 'unknown model')}), no DDM data")
            continue

        metrics = []
        if tx_dbm is not None:
            metrics.append(f"Tx={tx_dbm}dBm")
        if rx_dbm is not None:
            metrics.append(f"Rx={rx_dbm}dBm")
        if temp is not None:
            metrics.append(f"Temp={temp}C")
        if volt is not None:
            metrics.append(f"Vcc={volt}V")
        info.append(f"SFP on {port} ({data.get('type', '?')}): {', '.join(metrics)}")

        if rx_dbm is not None and rx_dbm < SFP_RX_LOW_DBM:
            warnings.append(f"Port {port}: SFP receive power {rx_dbm}dBm is below the "
                            f"{SFP_RX_LOW_DBM}dBm sensitivity floor (dirty or failing fiber)!")
        if temp is not None and temp > SFP_TEMP_HIGH_C:
            warnings.append(f"Port {port}: SFP temperature {temp}C exceeds "
                            f"{SFP_TEMP_HIGH_C}C!")
        if volt is not None and not SFP_VOLTAGE_RANGE[0] <= volt <= SFP_VOLTAGE_RANGE[1]:
            warnings.append(f"Port {port}: SFP supply voltage {volt}V is outside "
                            f"{SFP_VOLTAGE_RANGE[0]}-{SFP_VOLTAGE_RANGE[1]}V!")


def _check_pinned_settings(config, info):
    """Report ports with speed/duplex or MDI-X pinned in the running-config.

    This replaces a check that read the "MDI Mode" column of `show interface
    brief`. That column reports the mode a link NEGOTIATED, not the mode that
    was configured, so it read MDI/MDIX on essentially every connected port and
    flagged them all as anomalies — 30 of 40 ports on the switch it was tested
    against, none of which had anything pinned.
    """
    current_port = None
    for line in config.splitlines():
        m_int = _CONFIG_INTERFACE_RE.match(line)
        if m_int:
            current_port = m_int.group(1)
            continue
        m_set = _PINNED_SETTING_RE.match(line)
        if m_set and current_port:
            info.append(f"Port {current_port}: {m_set.group(1).lower()} pinned to "
                        f"{m_set.group(2)} (auto-negotiation disabled)")


def check_physical(sw):
    """Detects physical layer anomalies: speed/duplex, pinned settings, SFP DDM."""
    output_int_brief = sw.run('show interface brief')
    output_transceiver = sw.run('show interfaces transceiver detail')
    output_config = sw.run('show running-config', timeout=120)

    warnings = []
    info = []

    # Analyze interface brief
    for line in output_int_brief.splitlines():
        # Match lines like: 1/1  100/1000T  | Yes  Yes  Up   100FDx MDI   off  0
        m = re.match(r'^\s*([\w/]+)\s+.*?(Up|Down|Drop)\s+(\w+)\s+(MDIX|MDI|Auto)', line)
        if m:
            port, status, speed_mode, _mdix = m.groups()

            if status == 'Up':
                if 'HDx' in speed_mode:
                    warnings.append(f"Port {port}: Operating in Half-Duplex ({speed_mode})!")
                else:
                    # The Mode column is a speed+duplex word such as "1000FDx",
                    # never a bare "10"/"100"; matching the whole word against
                    # those made this branch unreachable.
                    m_speed = re.match(r'(\d+)', speed_mode)
                    if m_speed and int(m_speed.group(1)) < 1000:
                        # Could be a mismatch if gigabit was expected, but 100FDx
                        # is common for old printers. Informational only.
                        info.append(f"Port {port}: Operating below gigabit ({speed_mode})")

    _check_pinned_settings(output_config, info)
    _check_transceivers(output_transceiver, warnings, info)

    result = []
    if warnings:
        result.append("=== PHYSICAL WARNINGS ===")
        result.extend(warnings)
        result.append("")
    if info:
        result.append("=== PHYSICAL INFO ===")
        result.extend(info)
        result.append("")
    if not warnings and not info:
        result.append("No physical anomalies detected.")

    return '\n'.join(result)


def analyze_logs(sw):
    """Intelligent log analysis for STP, port flapping, and config events."""
    logs = sw.run('show log -r')

    warnings = []
    info = []

    # Trackers
    port_flaps = {}  # port -> list of timestamps
    config_changes = []  # timestamps of config saves
    stp_events = []

    # 1. First pass: Index events
    for line in logs.splitlines():
        # Example: I 03/08/26 11:34:16 00076 ports: port 1/A1 is now on-line
        m = re.match(r'^[A-Z]\s+(\d{2}/\d{2}/\d{2}\s+\d{2}:\d{2}:\d{2})\s+\d+\s+(\w+):\s+(.*)', line)
        if not m:
            continue

        timestamp_str, module, message = m.groups()

        try:
            # Assuming year format is '26' -> 2026. This won't work in 2100 :)
            dt = datetime.strptime(timestamp_str, '%m/%d/%y %H:%M:%S')
        except ValueError:
            continue

        # Track Port Flaps (Up/Down)
        if module == 'ports':
            m_port = re.search(r'port ([\w/]+) is now (on-line|off-line)', message)
            if m_port:
                port = m_port.group(1)
                event_type = m_port.group(2)
                if port not in port_flaps:
                    port_flaps[port] = []
                port_flaps[port].append((dt, event_type))

        # Track STP changes
        elif module == 'stpm':
            if 'CST Root changed' in message:
                stp_events.append((dt, line.strip()))
                warnings.append(f"WARNING [STP]: {line.strip()}")

        # Track Configuration changes
        elif module in ('cfgRestore', 'system', 'mgr'):
            if 'configuration changed' in message or 'Write memory' in message:
                config_changes.append(dt)
                info.append(f"Config Change: {timestamp_str} - {message}")

    # 2. Second pass: Analysis

    # Analyze Port Flapping
    # If a port went up and down more than 3 times in the last 24h of logs
    now = datetime.now()
    for port, events in port_flaps.items():
        # Sort chronologically (oldest to newest)
        events.sort(key=lambda x: x[0])

        # Count flaps in the last 24h
        recent_flaps = [e for e in events if (now - e[0]).total_seconds() <= 86400]
        if len(recent_flaps) >= 4:  # Up+Down+Up+Down = 4 events
            warnings.append(f"WARNING: Port {port} is FLAPPING! "
                            f"({len(recent_flaps)} state changes in the last 24h)")

    # Analyze Config vs Outages
    # Look for ports going offline within X minutes after a config change.
    # Only the FIRST outage per (port, config change) is reported: a flapping
    # port produces one line per off-line event otherwise, and the resulting
    # wall of near-identical alerts buries everything else in the report.
    for config_time in config_changes:
        for port, events in port_flaps.items():
            deltas = [(event_time - config_time).total_seconds()
                      for event_time, event_type in events if event_type == 'off-line']
            # 0..300s (5 min) after the change
            following = [d for d in deltas if 0 <= d <= 300]
            if not following:
                continue
            suffix = (f" (+{len(following) - 1} more outage(s) in the same window)"
                      if len(following) > 1 else "")
            warnings.append(
                f"CORRELATION ALERT: Port {port} went off-line {int(min(following))}s "
                f"after configuration change at "
                f"{config_time.strftime('%H:%M:%S')}!{suffix}")

    result = []
    if warnings:
        result.append("=== CRITICAL LOG EVENTS & CORRELATIONS ===")
        result.extend(warnings)
        result.append("")
    if info:
        result.append("=== NOTABLE SYSTEM EVENTS ===")
        result.extend(info)
        result.append("")
    if not warnings and not info:
        result.append("No critical events or suspicious patterns found in recent logs.")

    return '\n'.join(result)


def full_diagnose(sw):
    """Run all read-only diagnostic commands and save a timestamped report."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    hostname = sw.hostname or sw.host
    filename = f"diagnose_{hostname}_{timestamp}.txt"

    sections = [
        ('show version', lambda sw: sw.run('show version')),
        ('show vlan', get_vlans),
        ('show interface brief', get_interface_brief),
        ('show spanning-tree', get_spanning_tree),
        ('show lldp info remote-device', get_lldp_neighbors),
        ('show mac-address', get_mac_table),
        ('show log -r', get_logs),
        ('show running-config', get_running_config),
    ]

    report_parts = [
        f"Switch diagnosis: {hostname} ({sw.host})",
        f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
    ]

    for title, func in sections:
        print(f"  Running: {title}...")
        try:
            output = func(sw)
        except Exception as e:
            output = f"ERROR: {e}"
        report_parts.append(f"\n{'=' * 20} {title} {'=' * 20}")
        report_parts.append(output)

    report = '\n'.join(report_parts)

    with open(filename, 'w') as f:
        f.write(report)

    return filename

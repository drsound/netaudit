import re
import os
from datetime import datetime


def get_running_config(sw):
    return sw.run('show running-config', timeout=120)


def get_vlans(sw):
    return sw.run('show vlan')


def get_vlan(sw, vlan_id):
    return sw.run(f'show vlan {vlan_id}')


def get_spanning_tree(sw):
    return sw.run('show spanning-tree')


def get_interface_brief(sw):
    return sw.run('show interface brief')


def get_port_names(sw, port=None):
    output = sw.run('show name')
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


def get_lldp_neighbors(sw):
    return sw.run('show lldp info remote-device')


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

    # Look for topology change counters
    tc_count = re.search(r'(?:Topology Change Count|TCN Count)\s*[:\s]+(\d+)', output, re.IGNORECASE)
    if tc_count:
        count = int(tc_count.group(1))
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
        current_root = root_mac.group(1).lower()
        if expected_root_mac:
            expected_root = expected_root_mac.lower()
            if current_root != expected_root:
                warnings.append(f"WARNING: CST Root MAC ({current_root}) does NOT match expected Centro Stella ({expected_root})!")
            else:
                info.append(f"CST Root MAC ({current_root}) matches expected Centro Stella.")
        else:
            # Fallback: check if switch itself is root
            bridge_mac = re.search(r'(?:Switch|Bridge) MAC Address\s*:\s*([\w\-:]+)', summary_output)
            if bridge_mac and current_root != bridge_mac.group(1).lower():
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
        m_admin_edge = re.match(r'.*AdminEdgePort\s*:\s*(Yes|No)', line, re.IGNORECASE)
        m_oper_edge = re.match(r'.*OperEdgePort\s*:\s*(Yes|No)', line, re.IGNORECASE)
        m_root_guard = re.match(r'.*RootGuard\s*:\s*(Yes|No)', line, re.IGNORECASE)
        m_tcn_guard = re.match(r'.*TCNGuard\s*:\s*(Yes|No)', line, re.IGNORECASE)
        m_bpdu_protect = re.match(r'.*BPDUProtection\s*:\s*(Yes|No)', line, re.IGNORECASE)
        m_loop_guard = re.match(r'.*LoopGuard\s*:\s*(Yes|No)', line, re.IGNORECASE)
        
        if m_admin_edge: port_data[current_port]['admin_edge'] = m_admin_edge.group(1)
        if m_oper_edge: port_data[current_port]['oper_edge'] = m_oper_edge.group(1)
        if m_root_guard: port_data[current_port]['root_guard'] = m_root_guard.group(1)
        if m_tcn_guard: port_data[current_port]['tcn_guard'] = m_tcn_guard.group(1)
        if m_bpdu_protect: port_data[current_port]['bpdu_protect'] = m_bpdu_protect.group(1)
        if m_loop_guard: port_data[current_port]['loop_guard'] = m_loop_guard.group(1)

    # Analyze parsed port data
    for port, data in port_data.items():
        # Edge port receiving BPDUs
        if data.get('admin_edge') == 'Yes' and data.get('oper_edge') == 'No':
            warnings.append(f"Port {port}: Configured as Edge (Admin) but operating as Non-Edge (BPDUs received!)")
            
        active_guards = []
        for guard in ('root_guard', 'tcn_guard', 'bpdu_protect', 'loop_guard'):
            if data.get(guard) == 'Yes':
                active_guards.append(guard.replace('_', ' ').title())
        
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


def check_physical(sw):
    """Detects physical layer anomalies: speed/duplex, MDIX, and reads SFP DDM."""
    output_int_brief = sw.run('show interface brief')
    output_transceiver = sw.run('show interfaces transceiver detail')
    
    warnings = []
    info = []
    
    # Analyze interface brief
    for line in output_int_brief.splitlines():
        # Match lines like: 1/1  100/1000T  | Yes  Yes  Up   100FDx MDI   off  0
        m = re.match(r'^\s*([\w/]+)\s+.*?(Up|Down|Drop)\s+(\w+)\s+(MDIX|MDI|MDIX-?)', line)
        if m:
            port, status, speed_mode, mdix = m.groups()
            
            if status == 'Up':
                if 'HDx' in speed_mode:
                    warnings.append(f"Port {port}: Operating in Half-Duplex ({speed_mode})!")
                elif speed_mode in ('10', '100'):
                    # Could be mismatch if expected gigabit, but '100FDx' is common for old printers. Just info.
                    info.append(f"Port {port}: Operating at {speed_mode}")
                    
                if mdix in ('MDI', 'MDIX') and 'Auto' not in line:
                    info.append(f"Port {port}: non-Auto MDI/MDIX ({mdix})")
                    
    # Analyze transceiver detail (SFP DDM)
    if 'Invalid input' in output_transceiver or 'does not support' in output_transceiver:
        info.append("SFP DDM Diagnostics (show interfaces transceiver detail) not supported on this switch.")
    else:
        # Example: 1/A1     0.0000mW   0.0000mW   0.00mA   0.000V   0.000C
        # We look for alarms/warnings (usually indicated by asterisks or explicit text)
        ddm_found = False
        for line in output_transceiver.splitlines():
            m = re.match(r'^\s*([\w/]+)\s+([0-9.]+m?W)\s+([0-9.]+m?W)\s+([0-9.]+mA)\s+([0-9.]+V)\s+([0-9.]+C)', line)
            if m:
                ddm_found = True
                port = m.group(1)
                # Just report metrics for active SFPs
                info.append(f"SFP on {port}: Tx={m.group(2)}, Rx={m.group(3)}, Temp={m.group(6)}")
        
        if not ddm_found:
            info.append("No active SFP physical diagnostics found.")
            
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
            warnings.append(f"WARNING: Port {port} is FLAPPING! ({len(recent_flaps)} state changes in the last 24h)")
            
    # Analyze Config vs Outages
    # Look for ports going offline within X minutes after a config change
    for config_time in config_changes:
        for port, events in port_flaps.items():
            for event_time, event_type in events:
                if event_type == 'off-line':
                    delta = (event_time - config_time).total_seconds()
                    # If port went offline between 0 and 300 seconds (5 min) after config change
                    if 0 <= delta <= 300:
                        warnings.append(f"CORRELATION ALERT: Port {port} went off-line {int(delta)}s after configuration change at {config_time.strftime('%H:%M:%S')}!")

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

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
        warnings.append("ATTENZIONE: STP e' disabilitato su questo switch!")

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
        info.append("Questo switch E' il Root Bridge")

    # Look for topology change counters
    tc_count = re.search(r'(?:Topology Change Count|TCN Count)\s*[:\s]+(\d+)', output, re.IGNORECASE)
    if tc_count:
        count = int(tc_count.group(1))
        if count > 100:
            warnings.append(f"ATTENZIONE: Topology Change Count elevato: {count} (possibile loop STP)")
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
        info.append(f"Porte in Blocking: {', '.join(blocking_ports)}")
    if discarding_ports:
        warnings.append(f"Porte in Discarding (non-forwarding): {', '.join(discarding_ports)}")

    result = []
    if warnings:
        result.append("=== AVVISI STP ===")
        result.extend(warnings)
        result.append("")
    if info:
        result.append("=== INFO STP ===")
        result.extend(info)
        result.append("")
    result.append("=== OUTPUT COMPLETO ===")
    result.append(output)

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
        f"Diagnosi switch: {hostname} ({sw.host})",
        f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 60,
        "",
    ]

    for title, func in sections:
        print(f"  Eseguendo: {title}...")
        try:
            output = func(sw)
        except Exception as e:
            output = f"ERRORE: {e}"
        report_parts.append(f"\n{'=' * 20} {title} {'=' * 20}")
        report_parts.append(output)

    report = '\n'.join(report_parts)

    with open(filename, 'w') as f:
        f.write(report)

    return filename

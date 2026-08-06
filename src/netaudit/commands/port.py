"""Port status, naming, switchport configuration and host-to-port lookup."""

import argparse
import re
import sys
import textwrap
from collections import defaultdict

from netaudit import diagnostics, modifications
from netaudit.commands.base import Command
from netaudit.config import get_nmap_db
from netaudit.formatting import parse_mac_table, render_csv, render_table
from netaudit.nmap_parser import normalize_mac

USAGE = textwrap.dedent("""\
    usage:
      netaudit port access   <port> <vlan>      set port to access mode (untagged)
      netaudit port tag      <port> <vlan>      add port as tagged
      netaudit port untag    <port> <vlan>      remove port from tagged
      netaudit port set-name <port> "<name>"    set port name/comment ("" to remove it)
      netaudit port find     <ip|hostname|mac>  find which port a host is connected to
      netaudit port find --rogue                detect unmanaged switches (multi-MAC on edge ports)

    examples:
      netaudit --switch core_switch port access 1/3 10
      netaudit --switch core_switch port tag 2/A1 100
      netaudit --switch core_switch port set-name 1/2 "Aruba_AP_Office"
      netaudit --switch core_switch port set-name 1/2 ""
      netaudit --switch core_switch --yes port set-name 2/24 "TEST"
      netaudit --switch core_switch port find 10.168.0.3
      netaudit --switch core_switch port find DESKTOP-2G07OBV
      netaudit --switch core_switch port find --rogue""")

PORT_ACTIONS = ('access', 'tag', 'untag', 'set-name', 'find')

ROGUE_COLUMNS = ('MAC Address', 'IP', 'Hostname', 'Vendor', 'OS')

_WRITE_ACTIONS = {
    'set-name': modifications.set_port_name,
    'access': modifications.set_port_access,
    'tag': modifications.add_port_tagged,
    'untag': modifications.remove_port_tagged,
}


def cmd_ports(sw, args):
    print(diagnostics.get_interface_brief(sw, format_csv=args.csv))


def cmd_port_names(sw, args):
    print(diagnostics.get_port_names(sw, port=args.port, format_csv=args.csv))


def cmd_port(sw, args):
    action = args.port_args[0]
    if action == 'find':
        cmd_port_find(sw, args)
    else:
        _WRITE_ACTIONS[action](sw, args.port_args[1], args.port_args[2], yes=args.yes)


# --- port find ---

def _host_cells(nmap_db, mac):
    """Return [ip, hostname, vendor, os] for a normalized MAC, blanks if unknown."""
    host = nmap_db.host_by_mac(mac) if nmap_db else None
    if not host:
        return ['', '', '', '']
    return [host['ip'] or '', host['hostname'] or '', host['vendor'] or '', host['os'] or '']


def _macs_per_port(sw):
    """Map switch port -> list of MACs learned on it, in switch format."""
    _, rows = parse_mac_table(diagnostics.get_mac_table(sw))
    per_port = defaultdict(list)
    for row in rows:
        per_port[row['port'].strip()].append(row['mac'])
    return per_port


def _find_rogues(sw, args):
    """Report edge ports that have learned more than one MAC.

    A non-edge port with many MACs is normally a legitimate uplink, so only
    edge ports are flagged.
    """
    if not args.csv:
        print(f"Scanning MAC table on {sw.hostname} for rogue devices "
              f"(multi-MAC on edge ports)...")

    per_port = _macs_per_port(sw)
    edge_ports = diagnostics.get_edge_ports(sw)
    nmap_db = get_nmap_db(args)

    suspects = {port: macs for port, macs in per_port.items()
                if len(macs) > 1 and port in edge_ports}

    if args.csv:
        headers = ['Switch Port'] + list(ROGUE_COLUMNS)
        rows = [[port, mac] + _host_cells(nmap_db, mac)
                for port, macs in suspects.items() for mac in macs]
        if rows:
            print(render_csv(headers, rows))
        return

    if not suspects:
        print("\nNo rogue devices detected (no multi-MAC edge ports found).")
        return

    for port, macs in suspects.items():
        print(f"\n[!] POTENTIAL ROGUE DEVICE on Port {port}")
        print(f"    Reason: Port is OperEdge but learned {len(macs)} MAC addresses.")
        print("    MACs connected:")
        rows = [[mac] + _host_cells(nmap_db, mac) for mac in macs]
        print(render_table(list(ROGUE_COLUMNS), rows, indent='      ',
                           min_widths=[20, 16, 30, 20, 0]))


def _resolve_target(nmap_db, target):
    """Look up an nmap host by IP, MAC or hostname."""
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        return nmap_db.host_by_ip(target)
    if re.match(r'^[0-9a-fA-F]{2}[:\-]', target):
        return nmap_db.host_by_mac(target)
    target_lower = target.lower()
    return next((h for h in nmap_db.all_hosts() if h['hostname'].lower() == target_lower), None)


def _find_host(sw, args, target):
    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Error: no nmap DB available.", file=sys.stderr)
        print("Specify --nmap-db <path> or set the NETAUDIT_NMAP_DB environment variable.",
              file=sys.stderr)
        return

    host = _resolve_target(nmap_db, target)
    if not host:
        print(f"Host '{target}' not found in nmap DB.")
        return
    if not host['mac']:
        print(f"Host {host['ip']} found in nmap DB but without MAC address.")
        return

    label = host['hostname'] or host['ip']
    print(f"Searching for MAC {host['mac']} ({label}) in the switch MAC table...")

    # Parsing goes through parse_mac_table so this shares MAC_ROW_RE with the
    # rest of the code. A local copy of the row regex used to live here and had
    # drifted to the Comware xxxx-xxxx-xxxx form, so the lookup silently matched
    # nothing on the Aruba/ProCurve switches this tool mainly targets.
    _, rows = parse_mac_table(diagnostics.get_mac_table(sw))
    found = next((row for row in rows if normalize_mac(row['mac']) == host['mac']), None)

    if not found:
        print(f"\nMAC {host['mac']} ({label}) not found in the switch MAC table.")
        print("The device might be connected to another switch or be offline.")
        return

    print("\nHost found:")
    print(f"  IP:       {host['ip']}")
    print(f"  MAC:      {found['mac']}")
    if host['hostname']:
        print(f"  Hostname: {host['hostname']}")
    if host['vendor']:
        print(f"  Vendor:   {host['vendor']}")
    if host['os']:
        print(f"  OS:       {host['os']}")
    print(f"  Switch:   {sw.hostname}")
    print(f"  Port:     {found['port']}")
    print(f"  VLAN:     {found['vlan']}")


def cmd_port_find(sw, args):
    """Find which port a host is connected to, or detect rogue devices."""
    if '--rogue' in args.port_args:
        _find_rogues(sw, args)
        return

    targets = [a for a in args.port_args[1:] if not a.startswith('-')]
    if not targets:
        print(f"Error: 'port find' requires a target <ip|hostname|mac> (or --rogue)\n\n{USAGE}",
              file=sys.stderr)
        return
    _find_host(sw, args, targets[0])


def validate_port(args):
    port_args = args.port_args
    if not port_args:
        print(USAGE, file=sys.stderr)
        sys.exit(1)
    if port_args[0] not in PORT_ACTIONS:
        print(f"Error: sub-command '{port_args[0]}' not recognized\n\n{USAGE}", file=sys.stderr)
        sys.exit(1)
    if port_args[0] == 'find':
        if len(port_args) < 2 and '--rogue' not in port_args:
            print(f"Error: 'port find' requires <ip|hostname|mac> or --rogue\n\n{USAGE}",
                  file=sys.stderr)
            sys.exit(1)
    elif len(port_args) < 3:
        print(f"Error: 'port {port_args[0]}' requires <port> and <argument>\n\n{USAGE}",
              file=sys.stderr)
        sys.exit(1)


COMMANDS = [
    Command(
        name='ports',
        handler=cmd_ports,
        help='Port status',
        description='Runs "show interface brief": status, speed and mode for each port.',
    ),
    Command(
        name='port-names',
        handler=cmd_port_names,
        help='Show configured port names/comments',
        description=textwrap.dedent("""\
            Shows names/comments configured on the ports.

            usage:
              netaudit port-names             list all ports
              netaudit port-names 2/24        show only port 2/24"""),
        add_arguments=lambda p: p.add_argument(
            'port', nargs='?', default=None, metavar='PORT',
            help='Specific port (optional, e.g. 2/24)'),
    ),
    Command(
        name='port',
        handler=cmd_port,
        help='Configure port or find host by port',
        description=USAGE,
        add_arguments=lambda p: p.add_argument(
            'port_args', nargs=argparse.REMAINDER, metavar='ARGS',
            help='access|tag|untag|set-name <port> <vlan>  or  find <ip|hostname|mac> [--rogue]'),
        validate=validate_port,
    ),
]

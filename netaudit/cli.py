"""Argument parsing and dispatch. Command behaviour lives in netaudit.commands."""

import argparse
import sys
import textwrap

from netaudit import __version__
from netaudit.commands import REGISTRY
from netaudit.config import resolve_switch
from netaudit.switch import Switch

EPILOG = textwrap.dedent("""\
    read-only (no modifications):
      diagnose                        full diagnosis, saves timestamped report
      config                          full running-config
      vlans                           list all VLANs
      vlan <id>                       specific VLAN details
      stp                             Spanning Tree full output
      stp check                       STP analysis: TC count, blocking ports, root bridge
      stp detail                      per-port Edge/Guard status, root bridge check
      ports                           port status (interface brief)
      physical-check                  speed/duplex/MDIX anomalies and SFP DDM metrics
      macs [--port P] [--vlan V]      MAC table, filtered by port or VLAN
      neighbors                       LLDP neighbors (topology)
      logs                            system logs
      log-audit                       intelligent log analysis (STP, flapping, configs)
      port-names                      names/comments configured on each port
      query "<cmd>"                   run arbitrary read-only commands

    modify (shows preview and asks for confirmation; use --yes to bypass):
      vlan create <id> <name>         create VLAN
      vlan rename <id> <name>         rename VLAN
      vlan delete <id>                delete VLAN
      port access   <port> <vlan>     set port to access mode (untagged)
      port tag      <port> <vlan>     add port as tagged
      port untag    <port> <vlan>     remove port from tagged
      port set-name <port> "<name>"   set name ("" to remove it)
      save                            save configuration (write memory)

    nmap (no switch connection):
      inventory [--os win|linux|other] [--service <name>] [--list-services]
                                      active host inventory from nmap DB

    nmap + switch:
      port find <ip|hostname|mac>     find which port a host is connected to
      port find --rogue               detect unmanaged switches (multi-MAC on edge ports)
      macs                            MAC table enriched with nmap hostname/IP/vendor

    examples:
      netaudit --switch core_switch vlans
      netaudit --switch core_switch macs --port 2/14
      netaudit --switch core_switch port find 10.168.0.3
      netaudit --switch core_switch query "show spanning-tree detail 1/1"
      netaudit inventory --os win
      netaudit --host 10.168.13.100 --user admin --password secret vlans
""")


def build_parser():
    fmt = argparse.RawDescriptionHelpFormatter

    parser = argparse.ArgumentParser(
        prog='netaudit',
        description='Network switch diagnostic and management tool',
        formatter_class=fmt,
        epilog=EPILOG,
    )
    parser.add_argument('--version', action='version', version=f'netaudit {__version__}')
    parser.add_argument('--switch', metavar='NAME', help='Switch name from switches.yaml')
    parser.add_argument('--host', metavar='IP', help='Switch IP/hostname (alternative to --switch)')
    parser.add_argument('--user', metavar='USER', help='SSH username')
    parser.add_argument('--password', metavar='PASS', help='SSH password')
    parser.add_argument('--switches-file', metavar='PATH', dest='switches_file',
                        help='Path to switches.yaml (default: ./switches.yaml, '
                             'then ~/.config/netaudit/switches.yaml)')
    parser.add_argument('--yes', action='store_true',
                        help='Bypass interactive confirmation (for automation)')
    parser.add_argument('--nmap-db', metavar='PATH', dest='nmap_db',
                        help='Path to nmap XML file (default: ./nmap-output.xml)')
    parser.add_argument('--csv', action='store_true',
                        help='Format output as CSV where applicable')

    sub = parser.add_subparsers(dest='cmd', metavar='COMMAND', required=True)
    for command in REGISTRY.values():
        subparser = sub.add_parser(
            command.name,
            formatter_class=fmt,
            help=command.help,
            description=command.description or command.help,
        )
        if command.add_arguments:
            command.add_arguments(subparser)

    return parser


def run_command(command, args):
    """Open the switch connection if the command needs one, then dispatch."""
    if not command.needs_switch:
        command.handler(None, args)
        return

    conn = resolve_switch(args)
    quiet = args.csv

    if not quiet:
        print(f"Connecting to {conn['host']}...")
    with Switch(**conn) as sw:
        if not quiet:
            print(f"Connected to {sw.hostname}\n")
        command.handler(sw, args)


def main(argv=None):
    args = build_parser().parse_args(argv)
    command = REGISTRY[args.cmd]

    if command.validate:
        command.validate(args)

    try:
        run_command(command, args)
    except ConnectionError as e:
        print(f"Connection error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

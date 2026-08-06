"""MAC address table, optionally enriched with nmap host data."""

import textwrap

from netaudit import diagnostics
from netaudit.commands.base import Command
from netaudit.config import get_nmap_db
from netaudit.formatting import enrich_mac_table

DESCRIPTION = textwrap.dedent("""\
    Shows the switch MAC address table.
    If the nmap DB is available, adds IP / Hostname / Vendor / OS columns.

    usage:
      netaudit macs                        full table
      netaudit macs --port 1/3             MACs learned on port 1/3
      netaudit macs --vlan 2               MACs in VLAN 2
      netaudit macs --port 1/3 --vlan 2    combined filters""")


def cmd_macs(sw, args):
    raw = diagnostics.get_mac_table(sw, port=args.port, vlan=args.vlan)
    nmap_db = get_nmap_db(args)

    # Without an nmap DB the raw output is already the best plain-text answer,
    # but CSV still has to go through the parser to become machine-readable.
    if not nmap_db and not args.csv:
        print(raw)
        return

    print(enrich_mac_table(raw, nmap_db, show_services=args.services, as_csv=args.csv))


def _add_arguments(p):
    p.add_argument('--port', metavar='PORT', help='Filter by port (e.g. 1/3, 2/A1)')
    p.add_argument('--vlan', metavar='VLAN', help='Filter by VLAN (e.g. 2)')
    p.add_argument('--services', action='store_true', help='Include open nmap services column')


COMMANDS = [
    Command(
        name='macs',
        handler=cmd_macs,
        help='MAC address table (enriched with nmap data if available)',
        description=DESCRIPTION,
        add_arguments=_add_arguments,
    ),
]

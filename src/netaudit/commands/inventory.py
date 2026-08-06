"""Host inventory built from the nmap XML database — no switch connection."""

import os
import sys
import textwrap
from collections import Counter

from netaudit.commands.base import Command
from netaudit.config import get_nmap_db
from netaudit.formatting import render_csv, render_table
from netaudit.nmap_parser import NmapDB

USAGE = textwrap.dedent("""\
    usage:
      netaudit inventory                         all active hosts
      netaudit inventory --os win|linux|other    filter by OS
      netaudit inventory --service <name>        filter by open service
      netaudit inventory --list-services         show all available services in DB

    examples:
      netaudit inventory
      netaudit inventory --os win
      netaudit inventory --service ssh
      netaudit inventory --list-services
      netaudit --nmap-db /path/to/scan.xml inventory""")

COLUMNS = ('IP', 'MAC', 'Vendor', 'Hostname', 'OS')

#: Substring that must appear in the nmap OS string for each --os choice.
#: 'other' is the complement of all the named families.
_OS_FAMILIES = {'win': 'windows', 'linux': 'linux'}


def matches_os(host, os_filter):
    os_str = (host['os'] or '').lower()
    family = _OS_FAMILIES.get(os_filter)
    if family:
        return family in os_str
    return not any(f in os_str for f in _OS_FAMILIES.values())


def filter_hosts(hosts, os_filter=None, service=None):
    """Apply the --os and --service filters."""
    if os_filter:
        hosts = [h for h in hosts if matches_os(h, os_filter)]
    if service:
        wanted = service.lower()
        hosts = [h for h in hosts if any(s['name'].lower() == wanted for s in h['services'])]
    return hosts


def _print_service_index(nmap_db, hosts):
    counts = Counter(svc['name'] for h in hosts for svc in h['services'])
    print(f"Services in nmap DB ({os.path.basename(nmap_db.path)}):\n")
    for name, count in counts.most_common():
        print(f"  {name:<20} {count:>4} hosts")
    print("\nUse --service <name> to filter hosts.")


def cmd_inventory(sw, args):
    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Error: no nmap DB available.", file=sys.stderr)
        print("Specify --nmap-db <path> or set the NETAUDIT_NMAP_DB environment variable.",
              file=sys.stderr)
        print("Searched for: nmap-output.xml in the current directory.", file=sys.stderr)
        # Exit non-zero: this is a failure, and returning 0 made it invisible to
        # any script that checks the status code.
        sys.exit(1)

    hosts = nmap_db.all_hosts()

    if args.list_services:
        _print_service_index(nmap_db, hosts)
        return

    hosts = filter_hosts(hosts, os_filter=args.os_filter, service=args.service)

    headers = list(COLUMNS)
    if args.services:
        headers.append('Services')

    rows = [[h['ip'], h['mac'] or '', h['vendor'] or '', h['hostname'] or '', h['os'] or '']
            + ([NmapDB.format_services(h)] if args.services else [])
            for h in hosts]

    if args.csv:
        print(render_csv(headers, rows))
        return

    print(f"Nmap DB: {nmap_db.path}")
    filters = []
    if args.os_filter:
        filters.append(f"OS={args.os_filter}")
    if args.service:
        filters.append(f"service={args.service}")
    if filters:
        print(f"Filters: {', '.join(filters)}")

    if not hosts:
        print("No hosts found matching the specified filters.")
        return

    print(f"Found hosts: {len(hosts)}\n")
    max_widths = [None, 19, 20, 28, 40] + ([50] if args.services else [])
    print(render_table(headers, rows, min_widths=[15, 19, 0, 0, 0], max_widths=max_widths))


def _add_arguments(p):
    p.add_argument('--os', dest='os_filter', metavar='OS', choices=['win', 'linux', 'other'],
                   help='Filter by OS: win, linux, other')
    p.add_argument('--service', metavar='NAME',
                   help='Filter by open service name (e.g. http, rdp)')
    p.add_argument('--list-services', action='store_true',
                   help='List all detected services in DB with host counts')
    p.add_argument('--services', action='store_true', help='Include open nmap services column')


COMMANDS = [
    Command(
        name='inventory',
        handler=cmd_inventory,
        help='Active host inventory from nmap DB (no switch connection)',
        description=USAGE,
        add_arguments=_add_arguments,
        needs_switch=False,
    ),
]

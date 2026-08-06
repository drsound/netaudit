"""VLAN listing, inspection and management."""

import sys
import textwrap

from netaudit import diagnostics, modifications
from netaudit.commands.base import Command

USAGE = textwrap.dedent("""\
    usage:
      netaudit vlan <id>                    show detailed VLAN info
      netaudit vlan create <id> <name>      create VLAN (asks for confirmation)
      netaudit vlan rename <id> <new_name>  rename VLAN (asks for confirmation)
      netaudit vlan delete <id>             delete VLAN (asks for confirmation)

    examples:
      netaudit --switch core_switch vlan 2
      netaudit --switch core_switch vlan create 99 TEST
      netaudit --switch core_switch vlan rename 99 PRODUCTION
      netaudit --switch core_switch vlan delete 99
      netaudit --switch core_switch --yes vlan create 99 TEST""")


def cmd_vlans(sw, args):
    print(diagnostics.get_vlans(sw))


def cmd_vlan(sw, args):
    action = args.vlan_args[0]
    if action == 'create':
        modifications.create_vlan(sw, args.vlan_args[1], args.vlan_args[2], yes=args.yes)
    elif action == 'rename':
        modifications.rename_vlan(sw, args.vlan_args[1], args.vlan_args[2], yes=args.yes)
    elif action == 'delete':
        modifications.delete_vlan(sw, args.vlan_args[1], yes=args.yes)
    else:
        print(diagnostics.get_vlan(sw, action))


def validate_vlan(args):
    vlan_args = args.vlan_args
    if not vlan_args:
        print(USAGE, file=sys.stderr)
        sys.exit(1)
    if vlan_args[0] in ('create', 'rename') and len(vlan_args) < 3:
        print(f"Error: 'vlan {vlan_args[0]}' requires <id> and <name>\n\n{USAGE}", file=sys.stderr)
        sys.exit(1)
    if vlan_args[0] == 'delete' and len(vlan_args) < 2:
        print(f"Error: 'vlan delete' requires <id>\n\n{USAGE}", file=sys.stderr)
        sys.exit(1)


COMMANDS = [
    Command(
        name='vlans',
        handler=cmd_vlans,
        help='List all configured VLANs',
        description='Runs "show vlan" and prints the list of all VLANs.',
    ),
    Command(
        name='vlan',
        handler=cmd_vlan,
        help='Show or manage a VLAN',
        description=USAGE,
        add_arguments=lambda p: p.add_argument(
            'vlan_args', nargs='*', metavar='ARGS',
            help='id | create <id> <name> | rename <id> <name> | delete <id>'),
        validate=validate_vlan,
    ),
]

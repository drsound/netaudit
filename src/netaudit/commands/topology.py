"""LLDP neighbors and (planned) multi-switch topology traversal."""

from netaudit import diagnostics
from netaudit.commands.base import Command


def cmd_neighbors(sw, args):
    print(diagnostics.get_lldp_neighbors(sw, format_csv=args.csv))


def cmd_traverse(sw, args):
    print("Multi-switch traversal via LLDP: feature not yet implemented.")
    print("Local neighbors:")
    print(diagnostics.get_lldp_neighbors(sw))


def _traverse_arguments(p):
    p.add_argument('--start', metavar='SWITCH', help='Starting switch (default: the specified one)')
    p.add_argument('--depth', type=int, default=2, metavar='N', help='Discovery depth (default: 2)')


COMMANDS = [
    Command(
        name='neighbors',
        handler=cmd_neighbors,
        help='LLDP neighbors',
        description='Runs "show lldp info remote-device": shows connected\n'
                    'devices detected via LLDP (switches, APs, etc.).',
    ),
    Command(
        name='traverse',
        handler=cmd_traverse,
        help='[Future] Multi-switch topology traversal via LLDP',
        description='Automatic discovery of the network topology starting\n'
                    'from a switch and following LLDP neighbors. Not yet implemented.',
        add_arguments=_traverse_arguments,
    ),
]

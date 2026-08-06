"""Spanning Tree inspection and analysis."""

import textwrap

from netaudit import diagnostics
from netaudit.commands.base import Command

DESCRIPTION = textwrap.dedent("""\
    Show or analyze Spanning Tree (MSTP).

    usage:
      netaudit stp          full output of "show spanning-tree"
      netaudit stp check    automatic analysis: alerts for high TC count,
                            ports in Blocking/Discarding, root bridge info
      netaudit stp detail   deep analysis parsing per-port Edge/Guard status
                            and checking root bridge MAC against expected""")


def cmd_stp(sw, args):
    action = args.stp_args[0] if args.stp_args else None
    if action == 'check':
        print(diagnostics.check_stp_health(sw))
    elif action == 'detail':
        print(diagnostics.get_stp_detail(sw, sw._params.get('expected_root_mac')))
    else:
        print(diagnostics.get_spanning_tree(sw))


COMMANDS = [
    Command(
        name='stp',
        handler=cmd_stp,
        help='Spanning Tree Protocol',
        description=DESCRIPTION,
        add_arguments=lambda p: p.add_argument(
            'stp_args', nargs='*', metavar='ARGS', help='[check|detail]'),
    ),
]

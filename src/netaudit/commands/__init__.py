"""Command registry.

Every command owns its handler, its subparser definition and its argument
validation in one place; the CLI only walks this registry.
"""

from netaudit.commands import inventory, mac, port, stp, system, topology, vlan
from netaudit.commands.base import Command

_MODULES = (system, vlan, stp, port, mac, topology, inventory)

#: name -> Command, in the order the subparsers should be declared.
REGISTRY = {cmd.name: cmd for module in _MODULES for cmd in module.COMMANDS}

__all__ = ['Command', 'REGISTRY']

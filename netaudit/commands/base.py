"""The Command record shared by every command module."""

from dataclasses import dataclass
from typing import Callable, Optional


@dataclass(frozen=True)
class Command:
    """One netaudit subcommand.

    handler:       (switch_or_None, args) -> None
    add_arguments: (parser) -> None, called after the subparser is created
    validate:      (args) -> None, run before any SSH connection is opened;
                   should print to stderr and sys.exit(1) on bad input
    needs_switch:  False for commands that work purely on local data
    """

    name: str
    handler: Callable
    help: str
    description: str = ''
    add_arguments: Optional[Callable] = None
    validate: Optional[Callable] = None
    needs_switch: bool = True

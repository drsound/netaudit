"""Resolution and loading of the two external inputs: the switch inventory
(switches.yaml) and the optional nmap XML database."""

import os
import sys

import yaml

from netaudit.nmap_parser import NmapDB

#: Searched in order when neither --switches-file nor NETAUDIT_SWITCHES_FILE is set.
DEFAULT_SWITCHES_PATHS = (
    os.path.join(os.getcwd(), 'switches.yaml'),
    os.path.expanduser('~/.config/netaudit/switches.yaml'),
)

#: Inventory keys that configure the SSH connection. Every other key in a
#: switches.yaml entry is inventory metadata (model, location,
#: expected_root_mac, ...) and is carried alongside the connection instead.
CONNECTION_KEYS = ('host', 'user', 'password', 'device_type')

_nmap_db_cache = None


def switches_path(args):
    """Return the switches.yaml path to use, or None if no candidate exists.

    Priority: --switches-file > NETAUDIT_SWITCHES_FILE > ./switches.yaml >
    ~/.config/netaudit/switches.yaml
    """
    explicit = getattr(args, 'switches_file', None) or os.environ.get('NETAUDIT_SWITCHES_FILE')
    if explicit:
        return explicit
    for candidate in DEFAULT_SWITCHES_PATHS:
        if os.path.isfile(candidate):
            return candidate
    return None


def load_switches(args):
    """Load the switch inventory. Exits with a message if it cannot be read."""
    path = switches_path(args)
    if path is None:
        print("Error: no switches file found. Looked for:", file=sys.stderr)
        for candidate in DEFAULT_SWITCHES_PATHS:
            print(f"  {candidate}", file=sys.stderr)
        print("Pass --switches-file <path> or set NETAUDIT_SWITCHES_FILE.", file=sys.stderr)
        sys.exit(1)
    if not os.path.isfile(path):
        print(f"Error: switches file not found: {path}", file=sys.stderr)
        sys.exit(1)

    try:
        with open(path) as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        print(f"Error parsing {path}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict) or 'switches' not in data:
        print(f"Error: {path} has no top-level 'switches' key.", file=sys.stderr)
        sys.exit(1)
    return data['switches'] or {}


def split_switch_entry(entry):
    """Split a switches.yaml entry into (connection kwargs, inventory metadata).

    Keeping the two apart is what lets metadata reach the commands that need it:
    folding everything into the connection kwargs meant Switch.__init__ swallowed
    keys like expected_root_mac in **kwargs and no command could ever read them.
    """
    conn = {k: v for k, v in entry.items() if k in CONNECTION_KEYS}
    meta = {k: v for k, v in entry.items() if k not in CONNECTION_KEYS}
    return conn, meta


def resolve_switch(args):
    """Return (connection kwargs, metadata) from --switch or --host/--user/--password.

    The --host form carries no inventory, so its metadata is always empty.
    """
    if args.switch:
        switches = load_switches(args)
        if args.switch not in switches:
            print(f"Error: switch '{args.switch}' not found in the inventory.", file=sys.stderr)
            print(f"Available switches: {', '.join(switches)}", file=sys.stderr)
            sys.exit(1)
        return split_switch_entry(switches[args.switch])

    if args.host:
        if not args.user:
            print("Error: --host requires --user. Add --password if public key auth is not configured.",
                  file=sys.stderr)
            sys.exit(1)
        return {'host': args.host, 'user': args.user, 'password': args.password}, {}

    print("Error: specify either --switch <name> or --host/--user/--password", file=sys.stderr)
    sys.exit(1)


def get_nmap_db(args):
    """Load the nmap DB (cached per process). Returns None when unavailable."""
    global _nmap_db_cache
    if _nmap_db_cache is not None:
        return _nmap_db_cache

    path = (getattr(args, 'nmap_db', None)
            or os.environ.get('NETAUDIT_NMAP_DB')
            or NmapDB.find_db(os.getcwd()))

    if not path or not os.path.isfile(path):
        return None

    try:
        _nmap_db_cache = NmapDB(path)
    except Exception as e:
        print(f"Warning: unable to load nmap DB ({path}): {e}", file=sys.stderr)
        return None
    return _nmap_db_cache


def reset_nmap_cache():
    """Drop the cached nmap DB. Used by tests."""
    global _nmap_db_cache
    _nmap_db_cache = None

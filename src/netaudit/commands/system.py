"""Whole-switch operations: full diagnosis, running-config, logs, arbitrary
queries, physical layer checks and saving the configuration."""

from netaudit import diagnostics, modifications
from netaudit.commands.base import Command


def cmd_diagnose(sw, args):
    print(f"Starting full diagnosis of {sw.hostname} ({sw.host})...")
    filename = diagnostics.full_diagnose(sw)
    print(f"\nReport saved to: {filename}")


def cmd_config(sw, args):
    print(diagnostics.get_running_config(sw))


def cmd_logs(sw, args):
    print(diagnostics.get_logs(sw))


def cmd_log_audit(sw, args):
    print(f"Analyzing system logs on {sw.hostname}...")
    print(diagnostics.analyze_logs(sw))


def cmd_physical_check(sw, args):
    print(f"Running physical layer checks on {sw.hostname}...")
    print(diagnostics.check_physical(sw, scan_config=not args.no_config))


def cmd_query(sw, args):
    print(f"Executing: {args.command}\n" + "-" * 40)
    print(sw.run(args.command))


def cmd_save(sw, args):
    modifications.save_config(sw, yes=args.yes)


COMMANDS = [
    Command(
        name='diagnose',
        handler=cmd_diagnose,
        help='Full diagnosis — saves timestamped report to file',
        description='Runs all read-only commands and saves a report to\n'
                    'diagnose_<hostname>_<timestamp>.txt in the current directory.',
    ),
    Command(
        name='config',
        handler=cmd_config,
        help='Show full running-config',
        description='Runs "show running-config" and prints the output.',
    ),
    Command(
        name='logs',
        handler=cmd_logs,
        help='System logs',
        description='Runs "show log -r": system logs in reverse chronological order.',
    ),
    Command(
        name='log-audit',
        handler=cmd_log_audit,
        help='Intelligent log analysis',
        description='Analyzes system logs for STP route changes, port flapping loops,\n'
                    'and correlates configuration changes with immediate system issues.',
    ),
    Command(
        name='physical-check',
        handler=cmd_physical_check,
        help='Physical layer anomaly detection',
        description='Detects half-duplex and below-gigabit links, ports with speed-duplex or\n'
                    'mdix-mode pinned in the running-config, and reads SFP DDM metrics\n'
                    '(receive power, temperature, supply voltage) with alarm thresholds.\n\n'
                    'Reading the running-config dominates the runtime; --no-config skips it\n'
                    'and reports only link and optic health.',
        add_arguments=lambda p: p.add_argument(
            '--no-config', action='store_true',
            help='Skip the running-config scan for pinned speed-duplex/mdix-mode (faster)'),
    ),
    Command(
        name='query',
        handler=cmd_query,
        help='Execute arbitrary read-only commands',
        description='Runs a single command on the switch and prints the raw output.',
        add_arguments=lambda p: p.add_argument(
            'command', help='The command to execute (in quotes, e.g. "show version")'),
    ),
    Command(
        name='save',
        handler=cmd_save,
        help='Save configuration (write memory)',
        description='Runs "write memory" to make the current configuration permanent.\n'
                    'Asks for confirmation before proceeding.',
    ),
]

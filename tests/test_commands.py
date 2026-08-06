"""Regression tests for the two defects found during the package restructure."""

import textwrap

import pytest

from netaudit import diagnostics
from netaudit.cli import build_parser
from netaudit.commands import REGISTRY
from netaudit.commands import port as port_cmd
from netaudit.commands import stp as stp_cmd

# Leading whitespace is significant: the Aruba MAC row regex anchors on it.
RAW_MAC_TABLE = textwrap.dedent("""\
     Status and Counters - Port Address Table

      MAC Address   Port                    VLAN
      ------------- ----------------------- ----
      0001c0-17da89 1/23                    1
      aabbcc-ddeeff 2/A1                    10
    """)

ROGUE_MAC_TABLE = textwrap.dedent("""\
     Status and Counters - Port Address Table

      MAC Address   Port  VLAN
      ------------- ----- ----
      0001c0-17da89 1/23  1
      aabbcc-ddeeff 1/23  1
      001122-334455 1/24  1
      112233-445566 2/A1  1
      223344-556677 2/A1  1
    """)


class FakeSwitch:
    hostname = 'core-sw'
    host = '10.0.0.1'

    def __init__(self, meta=None, outputs=None):
        self.meta = meta or {}
        self._outputs = outputs or {}

    def run(self, cmd, timeout=30):
        return self._outputs.get(cmd, '')


@pytest.fixture
def use_nmap_db(monkeypatch, nmap_db):
    """Make the port commands see the in-memory nmap DB."""
    monkeypatch.setattr(port_cmd, 'get_nmap_db', lambda args: nmap_db)
    return nmap_db


@pytest.fixture
def no_nmap_db(monkeypatch):
    monkeypatch.setattr(port_cmd, 'get_nmap_db', lambda args: None)


def test_stp_detail_passes_expected_root_mac_from_inventory(monkeypatch, capsys):
    """expected_root_mac used to be dropped by Switch.__init__(**kwargs), so
    `stp detail` never checked the root bridge."""
    seen = {}

    def fake_detail(sw, expected_root_mac=None):
        seen['expected'] = expected_root_mac
        return 'detail output'

    monkeypatch.setattr(diagnostics, 'get_stp_detail', fake_detail)

    args = build_parser().parse_args(['--switch', 'core', 'stp', 'detail'])
    stp_cmd.cmd_stp(FakeSwitch(meta={'expected_root_mac': '00:11:22:33:44:55'}), args)

    assert seen['expected'] == '00:11:22:33:44:55'
    assert 'detail output' in capsys.readouterr().out


def test_stp_detail_without_inventory_metadata_passes_none(monkeypatch):
    seen = {}
    monkeypatch.setattr(diagnostics, 'get_stp_detail',
                        lambda sw, expected_root_mac=None: seen.setdefault('e', expected_root_mac))

    args = build_parser().parse_args(['--switch', 'core', 'stp', 'detail'])
    stp_cmd.cmd_stp(FakeSwitch(), args)

    assert seen['e'] is None


def test_stp_without_arguments_shows_the_plain_output(monkeypatch, capsys):
    monkeypatch.setattr(diagnostics, 'get_spanning_tree', lambda sw: 'plain stp')

    args = build_parser().parse_args(['--switch', 'core', 'stp'])
    stp_cmd.cmd_stp(FakeSwitch(), args)

    assert 'plain stp' in capsys.readouterr().out


def test_port_find_matches_aruba_format_macs(use_nmap_db, capsys):
    """The lookup regex expected the Comware xxxx-xxxx-xxxx form, so on Aruba
    switches `port find <target>` never matched anything."""
    sw = FakeSwitch(outputs={'show mac-address': RAW_MAC_TABLE})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '10.0.0.5'])

    port_cmd._find_host(sw, args, '10.0.0.5')
    out = capsys.readouterr().out

    assert 'Host found:' in out
    assert 'Port:     1/23' in out
    assert 'VLAN:     1' in out
    assert 'Hostname: DESKTOP-A' in out


def test_port_find_accepts_a_hostname_target(use_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': RAW_MAC_TABLE})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', 'nas01'])

    port_cmd._find_host(sw, args, 'nas01')
    out = capsys.readouterr().out

    assert 'Port:     2/A1' in out


def test_port_find_reports_a_host_absent_from_the_mac_table(use_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': "  MAC Address Port VLAN\n"})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '10.0.0.5'])

    port_cmd._find_host(sw, args, '10.0.0.5')

    assert 'not found in the switch MAC table' in capsys.readouterr().out


def test_port_find_without_an_nmap_db_explains_itself_and_exits_nonzero(no_nmap_db, capsys):
    """Missing DB is a failure: returning 0 hid it from any calling script."""
    sw = FakeSwitch(outputs={'show mac-address': RAW_MAC_TABLE})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '10.0.0.5'])

    with pytest.raises(SystemExit) as exc:
        port_cmd._find_host(sw, args, '10.0.0.5')

    assert exc.value.code == 1
    assert 'no nmap DB available' in capsys.readouterr().err


@pytest.mark.parametrize('target', [
    '0001c0-17da89',      # the notation `netaudit macs` prints
    '00:01:c0:17:da:89',  # colon form
    '0001C017DA89',       # bare, upper case
])
def test_port_find_resolves_a_mac_in_any_notation(use_nmap_db, capsys, target):
    """The MAC check required a separator at index 2, so the Aruba
    xxxxxx-xxxxxx form was treated as a hostname and never resolved."""
    sw = FakeSwitch(outputs={'show mac-address': RAW_MAC_TABLE})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', target])

    port_cmd._find_host(sw, args, target)
    out = capsys.readouterr().out

    assert 'Host found:' in out
    assert 'Port:     1/23' in out


def test_port_find_still_prefers_ip_over_mac_interpretation(use_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': RAW_MAC_TABLE})
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '10.0.0.9'])

    port_cmd._find_host(sw, args, '10.0.0.9')

    assert 'Port:     2/A1' in capsys.readouterr().out


def test_find_rogues_flags_only_multi_mac_edge_ports(monkeypatch, no_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': ROGUE_MAC_TABLE})
    # 1/23 is an edge port with two MACs -> rogue. 2/A1 also has two MACs but is
    # an uplink, so it must not be flagged; 1/24 is edge with a single MAC.
    monkeypatch.setattr(diagnostics, 'get_edge_ports', lambda sw: {'1/23', '1/24'})

    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '--rogue'])
    port_cmd._find_rogues(sw, args)
    out = capsys.readouterr().out

    assert 'POTENTIAL ROGUE DEVICE on Port 1/23' in out
    assert 'learned 2 MAC addresses' in out
    assert '2/A1' not in out
    assert '1/24' not in out


def test_find_rogues_reports_nothing_when_all_edge_ports_are_clean(monkeypatch, no_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': ROGUE_MAC_TABLE})
    monkeypatch.setattr(diagnostics, 'get_edge_ports', lambda sw: {'1/24'})

    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '--rogue'])
    port_cmd._find_rogues(sw, args)

    assert 'No rogue devices detected' in capsys.readouterr().out


def test_find_rogues_csv_stays_quiet_and_emits_one_row_per_mac(monkeypatch, use_nmap_db, capsys):
    sw = FakeSwitch(outputs={'show mac-address': ROGUE_MAC_TABLE})
    monkeypatch.setattr(diagnostics, 'get_edge_ports', lambda sw: {'1/23'})

    args = build_parser().parse_args(['--switch', 'core', '--csv', 'port', 'find', '--rogue'])
    port_cmd._find_rogues(sw, args)
    lines = capsys.readouterr().out.strip().splitlines()

    assert lines[0] == 'Switch Port,MAC Address,IP,Hostname,Vendor,OS'
    assert len(lines) == 3
    assert lines[1].startswith('1/23,0001c0-17da89,10.0.0.5,DESKTOP-A')


@pytest.mark.parametrize('argv', [
    ['port', 'find', '10.0.0.5', '--csv'],
    ['port', 'find', '--rogue', '--csv'],
    ['port', 'set-name', '2/24', 'x', '--yes'],
])
def test_port_rejects_global_flags_written_after_the_subcommand(argv, capsys):
    """argparse.REMAINDER hands these to `port` instead of parsing them, so they
    used to be accepted and silently ignored."""
    args = build_parser().parse_args(['--switch', 'core'] + argv)
    with pytest.raises(SystemExit):
        REGISTRY['port'].validate(args)

    assert 'Global flags go before the sub-command' in capsys.readouterr().err


def test_port_still_accepts_its_own_rogue_flag():
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '--rogue'])
    REGISTRY['port'].validate(args)


def test_confirm_without_a_terminal_refuses_instead_of_crashing(monkeypatch, capsys):
    """input() raises EOFError under cron or a pipe; that used to surface as a
    traceback. It must fail closed, never fall through to yes."""
    from netaudit import modifications

    def no_stdin(_prompt):
        raise EOFError

    monkeypatch.setattr('builtins.input', no_stdin)

    assert modifications._confirm() is False
    assert 'stdin is not a terminal' in capsys.readouterr().out


def test_confirm_with_yes_never_prompts(monkeypatch):
    from netaudit import modifications

    def boom(_prompt):
        raise AssertionError('must not prompt when --yes was given')

    monkeypatch.setattr('builtins.input', boom)
    assert modifications._confirm(yes=True) is True

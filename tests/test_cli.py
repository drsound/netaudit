import pytest

from netaudit.cli import build_parser
from netaudit.commands import REGISTRY

# Every command that existed before the package restructure must still parse.
EXPECTED_COMMANDS = {
    'diagnose', 'config', 'vlans', 'vlan', 'stp', 'ports', 'physical-check',
    'port-names', 'macs', 'neighbors', 'logs', 'log-audit', 'port', 'save',
    'traverse', 'inventory', 'query',
}


def test_registry_covers_every_command():
    assert set(REGISTRY) == EXPECTED_COMMANDS


def test_every_command_has_a_subparser():
    parser = build_parser()
    for name in REGISTRY:
        assert parser.parse_args(['--switch', 'core', name] if name != 'query'
                                 else ['--switch', 'core', name, 'show version']).cmd == name


def test_inventory_is_the_only_command_that_skips_the_switch():
    offline = {name for name, cmd in REGISTRY.items() if not cmd.needs_switch}
    assert offline == {'inventory'}


def test_global_flags_are_parsed():
    args = build_parser().parse_args(
        ['--switch', 'core', '--csv', '--yes', '--nmap-db', '/tmp/x.xml', 'ports'])

    assert args.switch == 'core'
    assert args.csv is True
    assert args.yes is True
    assert args.nmap_db == '/tmp/x.xml'


def test_macs_filters_are_parsed():
    args = build_parser().parse_args(['--switch', 'core', 'macs', '--port', '1/3', '--vlan', '2'])
    assert (args.port, args.vlan) == ('1/3', '2')


def test_port_find_keeps_its_arguments_verbatim():
    args = build_parser().parse_args(['--switch', 'core', 'port', 'find', '--rogue'])
    assert args.port_args == ['find', '--rogue']


def test_missing_command_is_an_error():
    with pytest.raises(SystemExit):
        build_parser().parse_args([])


def test_inventory_rejects_an_unknown_os_filter():
    with pytest.raises(SystemExit):
        build_parser().parse_args(['inventory', '--os', 'bsd'])


@pytest.mark.parametrize('argv', [
    ['vlan'],
    ['vlan', 'create', '99'],
    ['vlan', 'delete'],
])
def test_vlan_validation_rejects_incomplete_input(argv):
    args = build_parser().parse_args(['--switch', 'core'] + argv)
    with pytest.raises(SystemExit):
        REGISTRY['vlan'].validate(args)


def test_vlan_validation_accepts_a_complete_create():
    args = build_parser().parse_args(['--switch', 'core', 'vlan', 'create', '99', 'TEST'])
    REGISTRY['vlan'].validate(args)


@pytest.mark.parametrize('argv', [
    ['port'],
    ['port', 'bogus', '1/1', '10'],
    ['port', 'access', '1/1'],
    ['port', 'find'],
])
def test_port_validation_rejects_bad_input(argv):
    args = build_parser().parse_args(['--switch', 'core'] + argv)
    with pytest.raises(SystemExit):
        REGISTRY['port'].validate(args)


@pytest.mark.parametrize('argv', [
    ['port', 'access', '1/1', '10'],
    ['port', 'set-name', '2/24', 'AP office'],
    ['port', 'find', '10.0.0.5'],
    ['port', 'find', '--rogue'],
])
def test_port_validation_accepts_valid_input(argv):
    args = build_parser().parse_args(['--switch', 'core'] + argv)
    REGISTRY['port'].validate(args)

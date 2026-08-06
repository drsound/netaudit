import textwrap

import pytest

from netaudit import config

SWITCHES_YAML = textwrap.dedent("""\
    switches:
      core:
        host: 192.168.1.100
        user: admin
        password: secret
        device_type: aruba_osswitch
        model: "Aruba 2930M-24G"
        location: "Server Room"
        expected_root_mac: "00:11:22:33:44:55"
    """)


class Args:
    def __init__(self, **kw):
        self.switch = kw.get('switch')
        self.host = kw.get('host')
        self.user = kw.get('user')
        self.password = kw.get('password')
        self.switches_file = kw.get('switches_file')
        self.nmap_db = kw.get('nmap_db')


@pytest.fixture
def switches_file(tmp_path):
    path = tmp_path / 'switches.yaml'
    path.write_text(SWITCHES_YAML)
    return str(path)


def test_split_switch_entry_keeps_metadata_out_of_connection_kwargs():
    conn, meta = config.split_switch_entry({
        'host': '10.0.0.1', 'user': 'admin', 'password': 'p',
        'device_type': 'hp_procurve', 'model': 'HP 2530', 'expected_root_mac': 'aa:bb',
    })

    assert conn == {'host': '10.0.0.1', 'user': 'admin', 'password': 'p',
                    'device_type': 'hp_procurve'}
    assert meta == {'model': 'HP 2530', 'expected_root_mac': 'aa:bb'}


def test_resolve_switch_returns_metadata_from_inventory(switches_file):
    conn, meta = config.resolve_switch(Args(switch='core', switches_file=switches_file))

    assert conn['host'] == '192.168.1.100'
    assert conn['device_type'] == 'aruba_osswitch'
    # expected_root_mac used to be swallowed by **kwargs and never reached the
    # stp detail command.
    assert meta['expected_root_mac'] == '00:11:22:33:44:55'
    assert meta['location'] == 'Server Room'


def test_resolve_switch_from_host_flags_has_no_metadata():
    conn, meta = config.resolve_switch(Args(host='10.0.0.1', user='admin', password='p'))

    assert conn == {'host': '10.0.0.1', 'user': 'admin', 'password': 'p'}
    assert meta == {}


def test_resolve_switch_rejects_host_without_user():
    with pytest.raises(SystemExit):
        config.resolve_switch(Args(host='10.0.0.1'))


def test_resolve_switch_rejects_unknown_switch_name(switches_file):
    with pytest.raises(SystemExit):
        config.resolve_switch(Args(switch='nope', switches_file=switches_file))


def test_switches_path_prefers_the_explicit_flag(switches_file, monkeypatch):
    monkeypatch.setenv('NETAUDIT_SWITCHES_FILE', '/env/switches.yaml')
    assert config.switches_path(Args(switches_file=switches_file)) == switches_file


def test_switches_path_falls_back_to_the_environment(monkeypatch):
    monkeypatch.setenv('NETAUDIT_SWITCHES_FILE', '/env/switches.yaml')
    assert config.switches_path(Args()) == '/env/switches.yaml'


def test_load_switches_rejects_a_file_without_the_switches_key(tmp_path):
    path = tmp_path / 'bad.yaml'
    path.write_text('nodes: {}\n')
    with pytest.raises(SystemExit):
        config.load_switches(Args(switches_file=str(path)))

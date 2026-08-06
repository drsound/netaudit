from netaudit.commands.inventory import filter_hosts, matches_os

from .conftest import host

HOSTS = [
    host('10.0.0.1', os_name='Microsoft Windows 10', services=[('3389', 'rdp')]),
    host('10.0.0.2', os_name='Linux 5.4', services=[('22', 'ssh')]),
    host('10.0.0.3', os_name='HP ProCurve switch', services=[('22', 'ssh')]),
    host('10.0.0.4', os_name='', services=[]),
]


def test_matches_os_named_families():
    assert matches_os(HOSTS[0], 'win')
    assert not matches_os(HOSTS[1], 'win')
    assert matches_os(HOSTS[1], 'linux')


def test_matches_os_other_is_the_complement():
    assert matches_os(HOSTS[2], 'other')
    assert not matches_os(HOSTS[0], 'other')
    assert not matches_os(HOSTS[1], 'other')


def test_matches_os_treats_unknown_os_as_other():
    assert matches_os(HOSTS[3], 'other')


def test_filter_hosts_by_service_is_case_insensitive():
    result = filter_hosts(HOSTS, service='SSH')
    assert [h['ip'] for h in result] == ['10.0.0.2', '10.0.0.3']


def test_filter_hosts_combines_os_and_service():
    result = filter_hosts(HOSTS, os_filter='other', service='ssh')
    assert [h['ip'] for h in result] == ['10.0.0.3']


def test_filter_hosts_without_filters_is_a_passthrough():
    assert filter_hosts(HOSTS) == HOSTS

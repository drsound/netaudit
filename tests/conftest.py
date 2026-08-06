import pytest


def host(ip, mac=None, hostname='', vendor='', os_name='', services=()):
    """Build an nmap host record with the shape NmapDB._parse_host returns."""
    return {
        'ip': ip,
        'mac': mac,
        'vendor': vendor,
        'hostname': hostname,
        'os': os_name,
        'services': [{'port': p, 'proto': 'tcp', 'name': n, 'product': ''}
                     for p, n in services],
    }


class FakeNmapDB:
    """In-memory stand-in for NmapDB, keyed the same way."""

    path = '/fake/nmap-output.xml'

    def __init__(self, hosts):
        self._hosts = list(hosts)
        self._by_mac = {h['mac']: h for h in hosts if h['mac']}
        self._by_ip = {h['ip']: h for h in hosts}

    def host_by_mac(self, mac):
        from netaudit.nmap_parser import normalize_mac
        return self._by_mac.get(normalize_mac(mac))

    def host_by_ip(self, ip):
        return self._by_ip.get(ip)

    def all_hosts(self):
        return list(self._hosts)


@pytest.fixture
def nmap_db():
    return FakeNmapDB([
        host('10.0.0.5', '00:01:c0:17:da:89', 'DESKTOP-A', 'Advantech',
             'Microsoft Windows 10', services=[('3389', 'ms-wbt-server')]),
        host('10.0.0.9', 'aa:bb:cc:dd:ee:ff', 'nas01', 'Synology',
             'Linux 5.x', services=[('22', 'ssh'), ('80', 'http')]),
    ])

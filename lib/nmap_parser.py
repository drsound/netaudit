"""Parser per file XML nmap — database di inventario rete."""

import os
import re
import xml.etree.ElementTree as ET


def normalize_mac(mac):
    """Normalizza un MAC address in formato lowercase colon-separated (aa:bb:cc:dd:ee:ff)."""
    if not mac:
        return None
    digits = re.sub(r'[:\-\.]', '', mac).lower()
    if len(digits) != 12 or not re.match(r'^[0-9a-f]{12}$', digits):
        return None
    return ':'.join(digits[i:i + 2] for i in range(0, 12, 2))


def _ip_sort_key(ip):
    try:
        return tuple(int(p) for p in ip.split('.'))
    except Exception:
        return (0, 0, 0, 0)


class NmapDB:
    def __init__(self, xml_path):
        self.path = xml_path
        self._by_ip = {}
        self._by_mac = {}
        self._hosts = []
        self._parse(xml_path)

    def _parse(self, xml_path):
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host_el in root.findall('host'):
            status = host_el.find('status')
            if status is None or status.get('state') != 'up':
                continue
            h = self._parse_host(host_el)
            if not h['ip']:
                continue
            self._hosts.append(h)
            self._by_ip[h['ip']] = h
            if h['mac']:
                self._by_mac[h['mac']] = h
        self._hosts.sort(key=lambda h: _ip_sort_key(h['ip']))

    def _parse_host(self, host_el):
        ip = None
        mac = None
        vendor = None

        for addr_el in host_el.findall('address'):
            if addr_el.get('addrtype') == 'ipv4':
                ip = addr_el.get('addr')
            elif addr_el.get('addrtype') == 'mac':
                mac = normalize_mac(addr_el.get('addr', ''))
                vendor = addr_el.get('vendor', '')

        # Hostname from <hostnames>
        hostname = None
        hostnames_el = host_el.find('hostnames')
        if hostnames_el is not None:
            for hn_el in hostnames_el.findall('hostname'):
                if hn_el.get('name'):
                    hostname = hn_el.get('name')
                    break

        # OS from best osmatch
        os_name = None
        os_el = host_el.find('os')
        if os_el is not None:
            best_acc = -1
            for om in os_el.findall('osmatch'):
                acc = int(om.get('accuracy', '0'))
                if acc > best_acc:
                    best_acc = acc
                    os_name = om.get('name', '')

        # Services (open ports only)
        services = []
        ports_el = host_el.find('ports')
        if ports_el is not None:
            for port_el in ports_el.findall('port'):
                state_el = port_el.find('state')
                if state_el is None or state_el.get('state') != 'open':
                    continue
                svc_el = port_el.find('service')
                if svc_el is None:
                    continue
                svc_hostname = svc_el.get('hostname', '')
                if svc_hostname and not hostname:
                    hostname = svc_hostname
                services.append({
                    'port': port_el.get('portid'),
                    'proto': port_el.get('protocol'),
                    'name': svc_el.get('name', ''),
                    'product': svc_el.get('product', ''),
                })

        # Script results from <hostscript>
        hostscript_el = host_el.find('hostscript')
        if hostscript_el is not None:
            for script_el in hostscript_el.findall('script'):
                script_id = script_el.get('id', '')
                if script_id == 'nbstat':
                    for elem in script_el.iter('elem'):
                        if elem.get('key') == 'server_name' and elem.text:
                            hostname = elem.text.strip()
                            break
                elif script_id == 'smb-os-discovery':
                    for elem in script_el.iter('elem'):
                        k = elem.get('key', '')
                        if k == 'os' and elem.text:
                            os_name = elem.text.strip()
                        elif k == 'server' and elem.text and not hostname:
                            name = elem.text.strip()
                            # Strip literal \x00 suffix that nmap adds
                            if name.endswith('\\x00'):
                                name = name[:-4].strip()
                            if name:
                                hostname = name

        return {
            'ip': ip,
            'mac': mac,
            'vendor': vendor or '',
            'hostname': hostname or '',
            'os': os_name or '',
            'services': services,
        }

    def host_by_ip(self, ip):
        return self._by_ip.get(ip)

    def host_by_mac(self, mac):
        norm = normalize_mac(mac)
        if not norm:
            return None
        return self._by_mac.get(norm)

    def all_hosts(self):
        return list(self._hosts)

    @staticmethod
    def format_services(host):
        """Format host services into a compact comma-separated string."""
        if not host.get('services'):
            return ""
        
        # Format: 22/tcp(ssh), 80/tcp(http)
        svc_strings = []
        for svc in host['services']:
            name = svc.get('name', 'unknown')
            svc_strings.append(f"{svc['port']}/{svc['proto']}({name})")
        
        # Sort by port number
        svc_strings.sort(key=lambda s: int(s.split('/')[0]))
        return ", ".join(svc_strings)

    @staticmethod
    def find_db(directory=None):
        """Cerca nmap-output.xml nella directory specificata (default: directory corrente)."""
        if directory is None:
            directory = os.getcwd()
        path = os.path.join(directory, 'nmap-output.xml')
        return path if os.path.isfile(path) else None

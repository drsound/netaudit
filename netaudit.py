#!/usr/bin/env python3
"""netaudit — Network switch diagnostic and management tool (multi-vendor via netmiko)."""

import argparse
import os
import re
import sys
import textwrap
from collections import Counter

import yaml

from lib.switch import Switch
from lib import diagnostics, modifications

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
SWITCHES_FILE = os.path.join(SCRIPT_DIR, 'switches.yaml')

_nmap_db_cache = None


def load_switches():
    with open(SWITCHES_FILE) as f:
        return yaml.safe_load(f)['switches']


def resolve_switch(args):
    """Return connection kwargs from --switch or --host/--user/--password."""
    if args.switch:
        switches = load_switches()
        if args.switch not in switches:
            print(f"Error: switch '{args.switch}' not found in switches.yaml")
            print(f"Available switches: {', '.join(switches.keys())}")
            sys.exit(1)
        return switches[args.switch]
    elif args.host:
        if not args.user:
            print("Error: --host requires --user. Add --password if public key auth is not configured.")
            sys.exit(1)
        return {'host': args.host, 'user': args.user, 'password': args.password}
    else:
        print("Error: specify either --switch <name> or --host/--user/--password")
        sys.exit(1)


def get_nmap_db(args):
    """Loads and returns the nmap DB (cached). Returns None if not available."""
    global _nmap_db_cache
    if _nmap_db_cache is not None:
        return _nmap_db_cache

    path = None
    if hasattr(args, 'nmap_db') and args.nmap_db:
        path = args.nmap_db
    else:
        path = os.environ.get('NETAUDIT_NMAP_DB')
        if not path:
            from lib.nmap_parser import NmapDB
            path = NmapDB.find_db(os.getcwd())

    if not path or not os.path.isfile(path):
        return None

    try:
        from lib.nmap_parser import NmapDB
        _nmap_db_cache = NmapDB(path)
        return _nmap_db_cache
    except Exception as e:
        print(f"Warning: unable to load nmap DB ({path}): {e}", file=sys.stderr)
        return None


# --- Read commands ---

def cmd_diagnose(sw, args):
    print(f"Starting full diagnosis of {sw.hostname} ({sw.host})...")
    filename = diagnostics.full_diagnose(sw)
    print(f"\nReport saved to: {filename}")


def cmd_config(sw, args):
    print(diagnostics.get_running_config(sw))


def cmd_vlans(sw, args):
    print(diagnostics.get_vlans(sw))


VLAN_USAGE = textwrap.dedent("""\
    usage:
      netaudit vlan <id>                    show detailed VLAN info
      netaudit vlan create <id> <name>      create VLAN (asks for confirmation)
      netaudit vlan rename <id> <new_name>  rename VLAN (asks for confirmation)
      netaudit vlan delete <id>             delete VLAN (asks for confirmation)

    examples:
      netaudit --switch core_switch vlan 2
      netaudit --switch core_switch vlan create 99 TEST
      netaudit --switch core_switch vlan rename 99 PRODUCTION
      netaudit --switch core_switch vlan delete 99
      netaudit --switch core_switch --yes vlan create 99 TEST""")


def cmd_vlan(sw, args):
    action = args.vlan_args[0]
    if action == 'create':
        modifications.create_vlan(sw, args.vlan_args[1], args.vlan_args[2], yes=args.yes)
    elif action == 'rename':
        modifications.rename_vlan(sw, args.vlan_args[1], args.vlan_args[2], yes=args.yes)
    elif action == 'delete':
        modifications.delete_vlan(sw, args.vlan_args[1], yes=args.yes)
    else:
        print(diagnostics.get_vlan(sw, action))


def cmd_stp(sw, args):
    check = args.stp_args and args.stp_args[0] == 'check'
    detail = args.stp_args and args.stp_args[0] == 'detail'
    if check:
        print(diagnostics.check_stp_health(sw))
    elif detail:
        expected_root_mac = sw._params.get('expected_root_mac')
        print(diagnostics.get_stp_detail(sw, expected_root_mac))
    else:
        print(diagnostics.get_spanning_tree(sw))


def cmd_ports(sw, args):
    print(diagnostics.get_interface_brief(sw))


def _enrich_mac_table(raw, nmap_db, show_services=False, as_csv=False):
    """Replaces the raw MAC table with a fully enriched table including nmap data or formats it as CSV."""
    from lib.nmap_parser import normalize_mac, NmapDB
    import csv
    import io

    # Aruba MAC table format: "  0001c0-17da89     1/23    1   "
    # MAC is 12 hex chars split by ONE dash: xxxxxx-xxxxxx
    mac_re = re.compile(
        r'^\s+([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\d+)',
        re.IGNORECASE
    )

    title_lines = []
    rows = []
    in_data = False

    for line in raw.splitlines():
        if re.search(r'MAC\s+Address', line, re.IGNORECASE):
            in_data = True
            continue  # drop original header, we'll build our own
        if re.match(r'\s*-{5,}', line):
            continue  # drop separator lines too
        m = mac_re.match(line)
        if m and in_data:
            mac_raw = m.group(1)
            port = m.group(2)
            vlan = m.group(3)
            mac_norm = normalize_mac(mac_raw)
            host = nmap_db.host_by_mac(mac_norm) if mac_norm else None
            
            services_str = NmapDB.format_services(host) if host and show_services else ''
            
            rows.append({
                'mac': mac_raw,
                'port': port,
                'vlan': vlan,
                'ip':       host['ip']       if host else '',
                'hostname': host['hostname'] if host else '',
                'vendor':   host['vendor']   if host else '',
                'os':       host['os']       if host else '',
                'services': services_str,
            })
        elif not in_data:
            title_lines.append(line)

    if as_csv:
        output = io.StringIO()
        writer = csv.writer(output)
        
        headers = ['MAC Address', 'Port', 'VLAN', 'IP', 'Hostname', 'Vendor', 'OS']
        if show_services:
            headers.append('Services')
        writer.writerow(headers)
        
        for r in rows:
            row = [r['mac'], r['port'], r['vlan'], r['ip'], r['hostname'], r['vendor'], r['os']]
            if show_services:
                row.append(r['services'])
            writer.writerow(row)
            
        return output.getvalue().strip()

    # Column widths (auto-fit text format)
    col_mac  = max(18, max((len(r['mac'])      for r in rows), default=0) + 2)
    col_port = max(10, max((len(r['port'])     for r in rows), default=0) + 2)
    col_vlan = 6
    col_ip   = max(16, max((len(r['ip'])       for r in rows), default=0) + 2)
    col_host = max(24, max((len(r['hostname']) for r in rows), default=0) + 2)
    col_vend = max(20, max((len(r['vendor'])   for r in rows), default=0) + 2)
    col_os   = max(4, max((len(r['os'])       for r in rows), default=0) + 2)
    col_srv  = max(10, max((len(r['services']) for r in rows), default=0) + 2) if show_services else 0

    if show_services:
        hdr = (f"  {'MAC Address':<{col_mac - 1}} {'Port':<{col_port - 1}} {'VLAN':<{col_vlan - 1}}"
               f" {'IP':<{col_ip - 1}} {'Hostname':<{col_host - 1}} {'Vendor':<{col_vend - 1}} "
               f"{'OS':<{col_os - 1}} {'Services':<{col_srv - 1}}")
        sep = (
            '  ' + '-' * (col_mac - 1) + 
            ' ' + '-' * (col_port - 1) + 
            ' ' + '-' * (col_vlan - 1) +
            ' ' + '-' * (col_ip - 1) + 
            ' ' + '-' * (col_host - 1) + 
            ' ' + '-' * (col_vend - 1) + 
            ' ' + '-' * (col_os - 1) +
            ' ' + '-' * (col_srv - 1)
        )
    else:
        hdr = (f"  {'MAC Address':<{col_mac - 1}} {'Port':<{col_port - 1}} {'VLAN':<{col_vlan - 1}}"
               f" {'IP':<{col_ip - 1}} {'Hostname':<{col_host - 1}} {'Vendor':<{col_vend - 1}} {'OS':<{col_os - 1}}")
        sep = (
            '  ' + '-' * (col_mac - 1) + 
            ' ' + '-' * (col_port - 1) + 
            ' ' + '-' * (col_vlan - 1) +
            ' ' + '-' * (col_ip - 1) + 
            ' ' + '-' * (col_host - 1) + 
            ' ' + '-' * (col_vend - 1) + 
            ' ' + '-' * (col_os - 1)
        )

    lines_out = title_lines + [hdr, sep]
    for r in rows:
        if show_services:
            lines_out.append(
                f"  {r['mac']:<{col_mac - 1}} {r['port']:<{col_port - 1}} {r['vlan']:<{col_vlan - 1}}"
                f" {r['ip']:<{col_ip - 1}} {r['hostname']:<{col_host - 1}} {r['vendor']:<{col_vend - 1}} "
                f"{r['os'][:col_os - 1]:<{col_os - 1}} {r['services'][:col_srv - 1]:<{col_srv - 1}}"
            )
        else:
            lines_out.append(
                f"  {r['mac']:<{col_mac - 1}} {r['port']:<{col_port - 1}} {r['vlan']:<{col_vlan - 1}}"
                f" {r['ip']:<{col_ip - 1}} {r['hostname']:<{col_host - 1}} {r['vendor']:<{col_vend - 1}} {r['os'][:col_os - 1]:<{col_os - 1}}"
            )

    return '\n'.join(lines_out)


def cmd_physical_check(sw, args):
    print(f"Running physical layer checks on {sw.hostname}...")
    print(diagnostics.check_physical(sw))


def cmd_ports(sw, args):
    as_csv = getattr(args, 'csv', False)
    print(diagnostics.get_interface_brief(sw, format_csv=as_csv))


def cmd_log_audit(sw, args):
    print(f"Analyzing system logs on {sw.hostname}...")
    print(diagnostics.analyze_logs(sw))


def cmd_macs(sw, args):
    nmap_db = get_nmap_db(args)
    raw = diagnostics.get_mac_table(sw, port=args.port, vlan=args.vlan)
    
    as_csv = getattr(args, 'csv', False)
    show_srv = getattr(args, 'services', False)
    
    if nmap_db:
        print(_enrich_mac_table(raw, nmap_db, show_services=show_srv, as_csv=as_csv))
    else:
        # If no nmap DB and user wants CSV, we can still parse and format it as CSV
        # by passing an empty nmap_db proxy or adjusting logic. For now:
        if as_csv:
             # Fast fake class without refactoring the whole signature
             class FakeNmapDB:
                 def host_by_mac(self, mac): return None
             print(_enrich_mac_table(raw, FakeNmapDB(), show_services=show_srv, as_csv=True))
        else:
             print(raw)


def cmd_neighbors(sw, args):
    as_csv = getattr(args, 'csv', False)
    print(diagnostics.get_lldp_neighbors(sw, format_csv=as_csv))


def cmd_logs(sw, args):
    print(diagnostics.get_logs(sw))


def cmd_port_names(sw, args):
    as_csv = getattr(args, 'csv', False)
    print(diagnostics.get_port_names(sw, port=args.port, format_csv=as_csv))


PORT_USAGE = textwrap.dedent("""\
    usage:
      netaudit port access   <port> <vlan>      set port to access mode (untagged)
      netaudit port tag      <port> <vlan>      add port as tagged
      netaudit port untag    <port> <vlan>      remove port from tagged
      netaudit port set-name <port> "<name>"    set port name/comment ("" to remove it)
      netaudit port find     <ip|hostname|mac>  find which port a host is connected to
      netaudit port find --rogue                detect unmanaged switches (multi-MAC on non-edge)

    examples:
      netaudit --switch core_switch port access 1/3 10
      netaudit --switch core_switch port tag 2/A1 100
      netaudit --switch core_switch port set-name 1/2 "Aruba_AP_Office"
      netaudit --switch core_switch port set-name 1/2 ""
      netaudit --switch core_switch --yes port set-name 2/24 "TEST"
      netaudit --switch core_switch port find 10.168.0.3
      netaudit --switch core_switch port find DESKTOP-2G07OBV
      netaudit --switch core_switch port find --rogue""")


def cmd_port_find(sw, args):
    """Finds which port a host is connected to, or detects rogue devices."""
    from lib.nmap_parser import normalize_mac
    from collections import defaultdict
    import re

    # Parse args for find subset
    rogue_mode = '--rogue' in args.port_args
    targets = [a for a in args.port_args[1:] if a != '--rogue']
    
    if rogue_mode:
        print(f"Scanning MAC table on {sw.hostname} for rogue devices (multi-MAC on non-uplink ports)...")
        raw_macs = diagnostics.get_mac_table(sw)
        
        # Parse MAC table to count MACs per port
        # Aruba format: xxxxxx-xxxxxx (12 hex chars, single dash)
        mac_re = re.compile(r'^(\s+)([0-9a-f]{6}-[0-9a-f]{6})(\s+)(\S+)\s+(\d+)', re.IGNORECASE)
        line_re = re.compile(r'^(\s+)([0-9a-f]{6}-[0-9a-f]{6})')
        
        macs_per_port = defaultdict(list)
        for line in raw_macs.splitlines():
            if line_re.match(line):
                m = mac_re.match(line)
                if m:
                    mac = normalize_mac(m.group(2))
                    port = m.group(4).strip()
                    macs_per_port[port].append(mac)

        # Get STP detail to know which ports are Edge
        stp_detail = sw.run('show spanning-tree detail')
        edge_ports = set()
        current_port = None
        for line in stp_detail.splitlines():
            m_port = re.match(r'^\s*Port\s*:\s*([\w/]+)', line)
            if m_port:
                current_port = m_port.group(1)
            elif current_port and re.match(r'.*OperEdgePort\s*:\s*Yes', line, re.IGNORECASE):
                edge_ports.add(current_port)

        rogues_found = False
        nmap_db = get_nmap_db(args)
        as_csv = getattr(args, 'csv', False)
        
        if as_csv:
            import csv
            import io
            out = io.StringIO()
            writer = csv.writer(out)
            writer.writerow(['Switch Port', 'Device MAC', 'IP', 'Hostname', 'Vendor', 'OS'])
            
            for port, macs in macs_per_port.items():
                if len(macs) > 1 and port in edge_ports:
                    rogues_found = True
                    for mac in macs:
                        ip, hostname, vendor, os_info = "", "", "", ""
                        if nmap_db:
                            h = nmap_db.host_by_mac(mac)
                            if h:
                                ip = h['ip'] or ""
                                hostname = h['hostname'] or ""
                                vendor = h['vendor'] or ""
                                os_info = h['os'] or ""
                        writer.writerow([port, mac, ip, hostname, vendor, os_info])
            if rogues_found:
                print(out.getvalue().strip())
            return
        
        # Standard Text Output
        for port, macs in macs_per_port.items():
            # A rogue device is suspected if a port has multiple MACs AND is marked as an Edge port
            # (If it's not an Edge port, it's likely a legitimate uplink/switch)
            if len(macs) > 1 and port in edge_ports:
                rogues_found = True
                print(f"\n[!] POTENTIAL ROGUE DEVICE on Port {port}")
                print(f"    Reason: Port is OperEdge but learned {len(macs)} MAC addresses.")
                print(f"    MACs connected:")
                # Print header for MACs connected to this rogue port
                print(f"      {'MAC Address':<20} {'IP':<16} {'Hostname':<30} {'Vendor':<20} {'OS'}")
                print(f"      {'-'*20:<20} {'-'*16:<16} {'-'*30:<30} {'-'*20:<20} {'-'*20:<20}")

                for mac in macs:
                    ip, hostname, vendor, os_info = "", "", "", ""
                    if nmap_db:
                        h = nmap_db.host_by_mac(mac)
                        if h:
                            ip = h['ip'] or ""
                            hostname = h['hostname'] or ""
                            vendor = h['vendor'] or ""
                            os_info = h['os'] or ""
                    print(f"      {mac:<20} {ip:<16} {hostname:<30} {vendor:<20} {os_info}")

        if not rogues_found:
            print("\nNo rogue devices detected (no multi-MAC Edge ports found).")
            
        return

    # Normal target-based find
    if not targets:
        print(f"Error: 'port find' requires a target <ip|hostname|mac> (or --rogue)\n\n{PORT_USAGE}")
        return
        
    target = targets[0]

    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Error: no nmap DB available.")
        print("Specify --nmap-db <path> or set the NETAUDIT_NMAP_DB environment variable.")
        return

    # Resolve target → nmap host
    host = None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        host = nmap_db.host_by_ip(target)
    elif re.match(r'^[0-9a-fA-F]{2}[:\-]', target):
        host = nmap_db.host_by_mac(target)
    else:
        target_lower = target.lower()
        host = next((h for h in nmap_db.all_hosts() if h['hostname'].lower() == target_lower), None)

    if not host:
        print(f"Host '{target}' not found in nmap DB.")
        return

    if not host['mac']:
        print(f"Host {host['ip']} found in nmap DB but without MAC address.")
        return

    label = host['hostname'] or host['ip']
    print(f"Searching for MAC {host['mac']} ({label}) in the switch MAC table...")

    raw = diagnostics.get_mac_table(sw)

    mac_re = re.compile(r'^\s+([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})\s+(\S+)\s+(\d+)', re.IGNORECASE)
    target_mac = host['mac']
    found = None

    for line in raw.splitlines():
        m = mac_re.match(line)
        if m:
            if normalize_mac(m.group(1)) == target_mac:
                found = {'mac_raw': m.group(1), 'port': m.group(2), 'vlan': m.group(3)}
                break

    if found:
        print(f"\nHost found:")
        print(f"  IP:       {host['ip']}")
        print(f"  MAC:      {found['mac_raw']}")
        if host['hostname']:
            print(f"  Hostname: {host['hostname']}")
        if host['vendor']:
            print(f"  Vendor:   {host['vendor']}")
        if host['os']:
            print(f"  OS:       {host['os']}")
        print(f"  Switch:   {sw.hostname}")
        print(f"  Port:     {found['port']}")
        print(f"  VLAN:     {found['vlan']}")
    else:
        print(f"\nMAC {host['mac']} ({label}) not found in the switch MAC table.")
        print("The device might be connected to another switch or be offline.")


def cmd_port(sw, args):
    action = args.port_args[0]
    if action == 'find':
        cmd_port_find(sw, args)
    else:
        port = args.port_args[1]
        if action == 'set-name':
            modifications.set_port_name(sw, port, args.port_args[2], yes=args.yes)
        elif action == 'access':
            modifications.set_port_access(sw, port, args.port_args[2], yes=args.yes)
        elif action == 'tag':
            modifications.add_port_tagged(sw, port, args.port_args[2], yes=args.yes)
        elif action == 'untag':
            modifications.remove_port_tagged(sw, port, args.port_args[2], yes=args.yes)


def cmd_save(sw, args):
    modifications.save_config(sw, yes=args.yes)


def cmd_traverse(sw, args):
    print("Multi-switch traversal via LLDP: feature not yet implemented.")
    print("Local neighbors:")
    print(diagnostics.get_lldp_neighbors(sw))


def cmd_query(sw, args):
    """Executes arbitrary read-only commands."""
    print(f"Executing: {args.command}\n" + "-"*40)
    print(sw.run(args.command))


# --- Inventory command (no switch connection) ---

INVENTORY_USAGE = textwrap.dedent("""\
    usage:
      netaudit inventory                         all active hosts
      netaudit inventory --os win|linux|other    filter by OS
      netaudit inventory --service <name>        filter by open service
      netaudit inventory --list-services         show all available services in DB

    examples:
      netaudit inventory
      netaudit inventory --os win
      netaudit inventory --service ssh
      netaudit inventory --list-services
      netaudit --nmap-db /path/to/scan.xml inventory""")


def cmd_inventory(sw, args):
    """Shows active host inventory from nmap DB (no switch connection)."""
    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Error: no nmap DB available.")
        print("Specify --nmap-db <path> or set the NETAUDIT_NMAP_DB environment variable.")
        print("Searched for: nmap-output.xml in the current directory.")
        return

    hosts = nmap_db.all_hosts()

    if args.list_services:
        counts = Counter(svc['name'] for h in hosts for svc in h['services'])
        print(f"Services in nmap DB ({os.path.basename(nmap_db.path)}):\n")
        for name, count in counts.most_common():
            print(f"  {name:<20} {count:>4} hosts")
        print(f"\nUse --service <name> to filter hosts.")
        return

    if args.os_filter:
        def matches_os(h):
            os_str = h['os'].lower()
            if args.os_filter == 'win':
                return 'windows' in os_str
            elif args.os_filter == 'linux':
                return 'linux' in os_str
            else:  # 'other'
                return 'windows' not in os_str and 'linux' not in os_str
        hosts = [h for h in hosts if matches_os(h)]

    if args.service:
        svc_filter = args.service.lower()
        hosts = [h for h in hosts if any(s['name'].lower() == svc_filter for s in h['services'])]

    print(f"Nmap DB: {nmap_db.path}")
    if args.os_filter or args.service:
        filters = []
        if args.os_filter:
            filters.append(f"OS={args.os_filter}")
        if args.service:
            filters.append(f"service={args.service}")
        print(f"Filters: {', '.join(filters)}")

    as_csv = getattr(args, 'csv', False)
    show_services = getattr(args, 'services', False)
    from lib.nmap_parser import NmapDB
    
    if as_csv:
        import csv
        import io
        output = io.StringIO()
        writer = csv.writer(output)
        
        headers = ['IP', 'MAC', 'Vendor', 'Hostname', 'OS']
        if show_services:
            headers.append('Services')
        writer.writerow(headers)
        
        for h in hosts:
            row = [h['ip'], h['mac'] or '', h['vendor'] or '', h['hostname'] or '', h['os'] or '']
            if show_services:
                row.append(NmapDB.format_services(h))
            writer.writerow(row)
            
        print(output.getvalue().strip())
        return

    if not hosts:
        print("No hosts found matching the specified filters.")
        return

    print(f"Found hosts: {len(hosts)}\n")

    # Column widths
    col_ip = max(15, max(len(h['ip']) for h in hosts) + 1)
    col_mac = 19
    col_vendor = min(20, max((len(h['vendor']) for h in hosts if h['vendor']), default=6) + 1)
    col_host = min(28, max((len(h['hostname']) for h in hosts if h['hostname']), default=8) + 1)
    col_os = min(40, max((len(h['os']) for h in hosts if h['os']), default=2) + 2)
    col_srv = 0
    if show_services:
        col_srv = min(50, max((len(NmapDB.format_services(h)) for h in hosts), default=8) + 2)

    if show_services:
        fmt = f"{{:<{col_ip - 1}}} {{:<{col_mac - 1}}} {{:<{col_vendor - 1}}} {{:<{col_host - 1}}} {{:<{col_os - 1}}} {{:<{col_srv - 1}}}"
        sep = (
            '-' * (col_ip - 1) + 
            ' ' + '-' * (col_mac - 1) + 
            ' ' + '-' * (col_vendor - 1) + 
            ' ' + '-' * (col_host - 1) + 
            ' ' + '-' * (col_os - 1) + 
            ' ' + '-' * (col_srv - 1)
        )
        print(fmt.format('IP', 'MAC', 'Vendor', 'Hostname', 'OS', 'Services'))
    else:
        fmt = f"{{:<{col_ip - 1}}} {{:<{col_mac - 1}}} {{:<{col_vendor - 1}}} {{:<{col_host - 1}}} {{:<{col_os - 1}}}"
        sep = (
            '-' * (col_ip - 1) + 
            ' ' + '-' * (col_mac - 1) + 
            ' ' + '-' * (col_vendor - 1) + 
            ' ' + '-' * (col_host - 1) + 
            ' ' + '-' * (col_os - 1)
        )
        print(fmt.format('IP', 'MAC', 'Vendor', 'Hostname', 'OS'))
        
    print(sep)

    for h in hosts:
        vendor_str = (h['vendor'] or '')[:col_vendor - 1]
        hostname_str = (h['hostname'] or '')[:col_host - 1]
        os_str = (h['os'] or '')[:col_os - 1]
        if show_services:
            svc_str = NmapDB.format_services(h)[:col_srv - 1]
            print(fmt.format(h['ip'], h['mac'] or '', vendor_str, hostname_str, os_str, svc_str))
        else:
            print(fmt.format(h['ip'], h['mac'] or '', vendor_str, hostname_str, os_str))


# --- Parser ---

def build_parser():
    R = argparse.RawDescriptionHelpFormatter

    parser = argparse.ArgumentParser(
        prog='netaudit',
        description='Network switch diagnostic and management tool',
        formatter_class=R,
        epilog=textwrap.dedent("""\
            read-only (no modifications):
              diagnose                        full diagnosis, saves timestamped report
              config                          full running-config
              vlans                           list all VLANs
              vlan <id>                       specific VLAN details
              stp                             Spanning Tree full output
              stp check                       STP analysis: TC count, blocking ports, root bridge
              ports                           port status (interface brief)
              macs [--port P] [--vlan V]      MAC table, filtered by port or VLAN
              neighbors                       LLDP neighbors (topology)
              logs                            system logs
              log-audit                       intelligent log analysis (STP, flapping, configs)
              port-names                      names/comments configured on each port
              query "<cmd>"                   run arbitrary read-only commands

            modify (shows preview and asks for confirmation; use --yes to bypass):
              vlan create <id> <name>         create VLAN
              vlan delete <id>                delete VLAN
              port access   <port> <vlan>     set port to access mode (untagged)
              port tag      <port> <vlan>     add port as tagged
              port untag    <port> <vlan>     remove port from tagged
              port set-name <port> "<name>"   set name ("" to remove it)
              save                            save configuration (write memory)

            nmap (no switch connection):
              inventory [--os win|linux|other] [--service <name>] [--list-services]
                                              active host inventory from nmap DB

            nmap + switch:
              port find <ip|hostname|mac>     find which port a host is connected to
              port find --rogue               detect unmanaged switches (multi-MAC active on Edge ports)
              macs                            MAC table enriched with nmap hostname/IP/vendor

            examples:
              netaudit --switch core_switch vlans
              netaudit --switch core_switch macs --port 2/14
              netaudit --switch core_switch port find 10.168.0.3
              netaudit --switch core_switch port find DESKTOP-2G07OBV
              netaudit --switch core_switch query "show spanning-tree detail 1/1"
              netaudit inventory
              netaudit inventory --os win
              netaudit inventory --service rdp
              netaudit --host 10.168.13.100 --user admin --password secret vlans
        """),
    )
    parser.add_argument('--switch', metavar='NAME',
                        help='Switch name from switches.yaml')
    parser.add_argument('--host', metavar='IP',
                        help='Switch IP/hostname (alternative to --switch)')
    parser.add_argument('--user', metavar='USER', help='SSH Username')
    parser.add_argument('--password', metavar='PASS', help='SSH Password')
    parser.add_argument('--yes', action='store_true',
                        help='Bypass interactive confirmation (for automation/LLM)')
    parser.add_argument('--nmap-db', metavar='PATH', dest='nmap_db',
                        help='Path to nmap XML file (default: auto-detect map_rete*.xml)')

    parser.add_argument('--csv', action='store_true',
                        help='Format output as CSV where applicable')

    sub = parser.add_subparsers(dest='cmd', metavar='COMMAND')
    sub.required = True

    sub.add_parser('diagnose', formatter_class=R,
                   help='Full diagnosis — saves timestamped report to file',
                   description='Runs all read-only commands and saves a report to\n'
                               'diagnose_<hostname>_<timestamp>.txt in the current directory.')

    sub.add_parser('config', formatter_class=R,
                   help='Show full running-config',
                   description='Runs "show running-config" and prints output.')

    sub.add_parser('vlans', formatter_class=R,
                   help='List all configured VLANs',
                   description='Runs "show vlan" and prints the list of all VLANs.')

    sub.add_parser('vlan', formatter_class=R,
                   help='Show or manage a VLAN',
                   description=VLAN_USAGE,
                   ).add_argument('vlan_args', nargs='*', metavar='ARGS',
                                  help='id | create <id> <nome> | delete <id>')

    stp_p = sub.add_parser('stp', formatter_class=R,
                            help='Spanning Tree Protocol',
                            description=textwrap.dedent("""\
                                Show or analyze Spanning Tree (MSTP).

                                usage:
                                  netaudit stp          full output of "show spanning-tree"
                                  netaudit stp check    automatic analysis: alerts for high TC count,
                                                        ports in Blocking/Discarding, root bridge info
                                  netaudit stp detail   deep analysis parsing per-port Edge/Guard status
                                                        and checking root bridge MAC against expected"""))
    stp_p.add_argument('stp_args', nargs='*', metavar='ARGS',
                       help='[check|detail]')

    sub.add_parser('ports', formatter_class=R,
                   help='Port status',
                   description='Runs "show interface brief": status, speed, mode for each port.')

    sub.add_parser('physical-check', formatter_class=R,
                   help='Physical layer anomaly detection',
                   description='Detects speed/duplex mismatches, non-Auto MDI/MDIX, and reads SFP DDM metrics.')

    macs_p = sub.add_parser('macs', formatter_class=R,
                             help='MAC address table (enriched with nmap hostname if available)',
                             description=textwrap.dedent("""\
                                 Shows the switch MAC address table.
                                 If the nmap DB is available, adds a Hostname column.

                                 usage:
                                   netaudit macs                        full table
                                   netaudit macs --port 1/3             MACs learned on port 1/3
                                   netaudit macs --vlan 2               MACs in VLAN 2
                                   netaudit macs --port 1/3 --vlan 2    combined filters"""))
    macs_p.add_argument('--port', metavar='PORT', help='Filter by port (e.g. 1/3, 2/A1)')
    macs_p.add_argument('--vlan', metavar='VLAN', help='Filter by VLAN (e.g. 2)')
    macs_p.add_argument('--services', action='store_true', help='Include open nmap services column')

    pn = sub.add_parser('port-names', formatter_class=R,
                        help='Show configured port names/comments',
                        description=textwrap.dedent("""\
                            Shows names/comments configured on the ports.

                            usage:
                              netaudit port-names             list all ports
                              netaudit port-names 2/24        show only port 2/24"""))
    pn.add_argument('port', nargs='?', default=None, metavar='PORT',
                    help='Specific port (optional, e.g. 2/24)')

    sub.add_parser('neighbors', formatter_class=R,
                   help='LLDP neighbors',
                   description='Runs "show lldp info remote-device": shows connected\n'
                               'devices detected via LLDP (switches, APs, etc.).')

    sub.add_parser('logs', formatter_class=R,
                   help='System logs',
                   description='Runs "show log -r": system logs in reverse chronological order.')

    sub.add_parser('log-audit', formatter_class=R,
                   help='Intelligent log analysis',
                   description='Analyzes system logs for STP route changes, port flapping loops,\n'
                               'and correlates configuration changes with immediate system issues.')

    sub.add_parser('port', formatter_class=R,
                   help='Configure port or find host by port',
                   description=PORT_USAGE,
                   ).add_argument('port_args', nargs=argparse.REMAINDER, metavar='ARGS',
                                  help='access|tag|untag|set-name <port> <vlan>  or  find <ip|hostname|mac> [--rogue]')

    sub.add_parser('save', formatter_class=R,
                   help='Save configuration (write memory)',
                   description='Runs "write memory" to make the current configuration permanent.\n'
                               'Asks for confirmation before proceeding.')

    traverse_p = sub.add_parser('traverse', formatter_class=R,
                                 help='[Future] Multi-switch topology traversal via LLDP',
                                 description='Automatic discovery of the network topology starting\n'
                                             'from a switch and following LLDP neighbors. Not yet implemented.')
    traverse_p.add_argument('--start', metavar='SWITCH', help='Starting switch (default: the specified one)')
    traverse_p.add_argument('--depth', type=int, default=2, metavar='N',
                             help='Discovery depth (default: 2)')

    inv_p = sub.add_parser('inventory', formatter_class=R,
                            help='Active host inventory from nmap DB (no switch connection)',
                            description=INVENTORY_USAGE)
    inv_p.add_argument('--os', dest='os_filter', metavar='OS',
                       choices=['win', 'linux', 'other'],
                       help='Filter by OS: win, linux, other')
    inv_p.add_argument('--service', metavar='NAME',
                       help='Filter by open service name (e.g. http, rdp)')
    inv_p.add_argument('--list-services', action='store_true',
                       help='List all detected services in DB with host counts')
    inv_p.add_argument('--services', action='store_true', help='Include open nmap services column')

    query_p = sub.add_parser('query', formatter_class=R,
                             help='Execute arbitrary read-only commands')
    query_p.add_argument('command', help='The command to execute (in quotes, e.g. "show version")')

    return parser


COMMANDS = {
    'diagnose': cmd_diagnose,
    'config': cmd_config,
    'vlans': cmd_vlans,
    'vlan': cmd_vlan,
    'stp': cmd_stp,
    'ports': cmd_ports,
    'physical-check': cmd_physical_check,
    'port-names': cmd_port_names,
    'macs': cmd_macs,
    'neighbors': cmd_neighbors,
    'logs': cmd_logs,
    'log-audit': cmd_log_audit,
    'port': cmd_port,
    'save': cmd_save,
    'traverse': cmd_traverse,
    'inventory': cmd_inventory,
    'query': cmd_query,
}

# Commands that do not require switch connection
SWITCH_NOT_REQUIRED = {'inventory'}


def validate_args(args):
    """Validates arguments before opening the SSH connection."""
    if args.cmd == 'vlan':
        vlan_args = args.vlan_args
        if not vlan_args:
            print(VLAN_USAGE, file=sys.stderr)
            sys.exit(1)
        if vlan_args[0] in ('create', 'rename') and len(vlan_args) < 3:
            print(f"Error: 'vlan {vlan_args[0]}' requires <id> and <name>\n\n{VLAN_USAGE}", file=sys.stderr)
            sys.exit(1)
        if vlan_args[0] == 'delete' and len(vlan_args) < 2:
            print(f"Error: 'vlan delete' requires <id>\n\n{VLAN_USAGE}", file=sys.stderr)
            sys.exit(1)

    if args.cmd == 'port':
        port_args = args.port_args
        if not port_args:
            print(PORT_USAGE, file=sys.stderr)
            sys.exit(1)
        if port_args[0] not in ('access', 'tag', 'untag', 'set-name', 'find'):
            print(f"Error: sub-command '{port_args[0]}' not recognized\n\n{PORT_USAGE}", file=sys.stderr)
            sys.exit(1)
        if port_args[0] == 'find':
            if len(port_args) < 2 and '--rogue' not in port_args:
                print(f"Error: 'port find' requires <ip|hostname|mac> or --rogue\n\n{PORT_USAGE}", file=sys.stderr)
                sys.exit(1)
        elif len(port_args) < 3:
            print(f"Error: 'port {port_args[0]}' requires <port> and <argument>\n\n{PORT_USAGE}", file=sys.stderr)
            sys.exit(1)


def main():
    parser = build_parser()
    args = parser.parse_args()

    validate_args(args)

    if args.cmd in SWITCH_NOT_REQUIRED:
        COMMANDS[args.cmd](None, args)
        return

    sw_config = resolve_switch(args)
    handler = COMMANDS[args.cmd]

    quiet = getattr(args, 'csv', False)
    if not quiet:
        print(f"Connecting to {sw_config['host']}...")
    try:
        with Switch(**sw_config) as sw:
            if not quiet:
                print(f"Connected to {sw.hostname}\n")
            handler(sw, args)
    except ConnectionError as e:
        print(f"Connection error: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(1)


if __name__ == '__main__':
    main()

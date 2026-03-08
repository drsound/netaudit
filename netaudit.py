#!/usr/bin/env python3
"""netaudit — Tool di diagnostica e gestione switch di rete (multi-vendor via netmiko)."""

import argparse
import os
import re
import sys
import textwrap

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
            print(f"Errore: switch '{args.switch}' non trovato in switches.yaml")
            print(f"Switch disponibili: {', '.join(switches.keys())}")
            sys.exit(1)
        return switches[args.switch]
    elif args.host:
        if not args.user or not args.password:
            print("Errore: --host richiede anche --user e --password")
            sys.exit(1)
        return {'host': args.host, 'user': args.user, 'password': args.password}
    else:
        print("Errore: specificare --switch <nome> oppure --host/--user/--password")
        sys.exit(1)


def get_nmap_db(args):
    """Carica e restituisce il DB nmap (cached). Restituisce None se non disponibile."""
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
        print(f"Avviso: impossibile caricare DB nmap ({path}): {e}", file=sys.stderr)
        return None


# --- Comandi lettura ---

def cmd_diagnose(sw, args):
    print(f"Avvio diagnosi completa di {sw.hostname} ({sw.host})...")
    filename = diagnostics.full_diagnose(sw)
    print(f"\nReport salvato in: {filename}")


def cmd_config(sw, args):
    print(diagnostics.get_running_config(sw))


def cmd_vlans(sw, args):
    print(diagnostics.get_vlans(sw))


VLAN_USAGE = textwrap.dedent("""\
    uso:
      netaudit vlan <id>                    mostra dettaglio VLAN
      netaudit vlan create <id> <nome>      crea VLAN (chiede conferma)
      netaudit vlan rename <id> <nuovo>     rinomina VLAN (chiede conferma)
      netaudit vlan delete <id>             elimina VLAN (chiede conferma)

    esempi:
      netaudit --switch centro_stella vlan 2
      netaudit --switch centro_stella vlan create 99 TEST
      netaudit --switch centro_stella vlan rename 99 PRODUZIONE
      netaudit --switch centro_stella vlan delete 99
      netaudit --switch centro_stella --yes vlan create 99 TEST""")


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
    if check:
        print(diagnostics.check_stp_health(sw))
    else:
        print(diagnostics.get_spanning_tree(sw))


def cmd_ports(sw, args):
    print(diagnostics.get_interface_brief(sw))


def _enrich_mac_table(raw, nmap_db):
    """Aggiunge colonna Hostname all'output di show mac-address usando il DB nmap."""
    from lib.nmap_parser import normalize_mac

    mac_re = re.compile(r'^(\s+)([0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4})(\s+\S+\s+\d+.*)', re.IGNORECASE)
    lines = raw.splitlines()
    result = []
    header_done = False

    for line in lines:
        if not header_done and re.search(r'MAC\s+Address', line, re.IGNORECASE):
            result.append(line + '   Hostname')
            header_done = True
        elif header_done and re.match(r'\s*-{5,}', line):
            result.append(line.rstrip() + '   ' + '-' * 24)
        else:
            m = mac_re.match(line)
            if m:
                mac = normalize_mac(m.group(2))
                host = nmap_db.host_by_mac(mac) if mac else None
                hostname = host['hostname'] if (host and host['hostname']) else ''
                result.append(line.rstrip() + '   ' + hostname)
            else:
                result.append(line)

    return '\n'.join(result)


def cmd_macs(sw, args):
    nmap_db = get_nmap_db(args)
    raw = diagnostics.get_mac_table(sw, port=args.port, vlan=args.vlan)
    if nmap_db:
        print(_enrich_mac_table(raw, nmap_db))
    else:
        print(raw)


def cmd_neighbors(sw, args):
    print(diagnostics.get_lldp_neighbors(sw))


def cmd_logs(sw, args):
    print(diagnostics.get_logs(sw))


def cmd_port_names(sw, args):
    print(diagnostics.get_port_names(sw, port=args.port))


PORT_USAGE = textwrap.dedent("""\
    uso:
      netaudit port access   <porta> <vlan>      imposta porta in access mode (untagged)
      netaudit port tag      <porta> <vlan>      aggiunge porta come tagged
      netaudit port untag    <porta> <vlan>      rimuove porta da tagged
      netaudit port set-name <porta> "<nome>"    imposta nome sulla porta ("" per rimuoverlo)
      netaudit port find     <ip|hostname|mac>   trova su quale porta è connesso un host

    esempi:
      netaudit --switch centro_stella port access 1/3 10
      netaudit --switch centro_stella port tag 2/A1 100
      netaudit --switch centro_stella port set-name 1/2 "AP_Aruba_Ufficio"
      netaudit --switch centro_stella port set-name 1/2 ""
      netaudit --switch centro_stella --yes port set-name 2/24 "TEST"
      netaudit --switch centro_stella port find 10.168.0.3
      netaudit --switch centro_stella port find DESKTOP-2G07OBV""")


def cmd_port_find(sw, target, args):
    """Trova su quale porta dello switch è connesso un host (tramite correlazione MAC/nmap)."""
    from lib.nmap_parser import normalize_mac

    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Errore: nessun DB nmap disponibile.")
        print("Specifica --nmap-db <path> o imposta la variabile NETAUDIT_NMAP_DB.")
        return

    # Risolvi target → host nmap
    host = None
    if re.match(r'^\d+\.\d+\.\d+\.\d+$', target):
        host = nmap_db.host_by_ip(target)
    elif re.match(r'^[0-9a-fA-F]{2}[:\-]', target):
        host = nmap_db.host_by_mac(target)
    else:
        target_lower = target.lower()
        host = next((h for h in nmap_db.all_hosts() if h['hostname'].lower() == target_lower), None)

    if not host:
        print(f"Host '{target}' non trovato nel DB nmap.")
        return

    if not host['mac']:
        print(f"Host {host['ip']} trovato nel DB nmap ma senza MAC address.")
        return

    label = host['hostname'] or host['ip']
    print(f"Ricerca MAC {host['mac']} ({label}) nella tabella dello switch...")

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
        print(f"\nHost trovato:")
        print(f"  IP:       {host['ip']}")
        print(f"  MAC:      {found['mac_raw']}")
        if host['hostname']:
            print(f"  Hostname: {host['hostname']}")
        if host['os']:
            print(f"  OS:       {host['os']}")
        print(f"  Switch:   {sw.hostname}")
        print(f"  Porta:    {found['port']}")
        print(f"  VLAN:     {found['vlan']}")
    else:
        print(f"\nMAC {host['mac']} ({label}) non trovato nella tabella MAC dello switch.")
        print("Il dispositivo potrebbe essere connesso a un altro switch o essere offline.")


def cmd_port(sw, args):
    action = args.port_args[0]
    if action == 'find':
        cmd_port_find(sw, args.port_args[1], args)
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
    print("Traversata multi-switch via LLDP: funzione non ancora implementata.")
    print("Neighbors locali:")
    print(diagnostics.get_lldp_neighbors(sw))


# --- Comando inventory (nessuna connessione switch) ---

INVENTORY_USAGE = textwrap.dedent("""\
    uso:
      netaudit inventory                         tutti gli host attivi
      netaudit inventory --os win|linux|other    filtra per OS
      netaudit inventory --service <nome>        filtra per servizio aperto
      netaudit inventory --list-services         mostra tutti i servizi disponibili nel DB

    esempi:
      netaudit inventory
      netaudit inventory --os win
      netaudit inventory --service ssh
      netaudit inventory --list-services
      netaudit --nmap-db /path/to/scan.xml inventory""")


def cmd_inventory(sw, args):
    """Mostra inventario host attivi dal DB nmap (nessuna connessione switch)."""
    nmap_db = get_nmap_db(args)
    if not nmap_db:
        print("Errore: nessun DB nmap disponibile.")
        print("Specifica --nmap-db <path> o imposta la variabile NETAUDIT_NMAP_DB.")
        print("File cercato: nmap-output.xml nella directory corrente.")
        return

    hosts = nmap_db.all_hosts()

    if args.list_services:
        from collections import Counter
        counts = Counter(svc['name'] for h in hosts for svc in h['services'])
        print(f"Servizi nel DB nmap ({os.path.basename(nmap_db.path)}):\n")
        for name, count in counts.most_common():
            print(f"  {name:<20} {count:>4} host")
        print(f"\nUsa --service <nome> per filtrare gli host.")
        return

    if args.os_filter:
        def matches_os(h):
            os_str = h['os'].lower()
            if args.os_filter == 'win':
                return 'windows' in os_str
            elif args.os_filter == 'linux':
                return 'linux' in os_str
            elif args.os_filter == 'other':
                return 'windows' not in os_str and 'linux' not in os_str
            return True
        hosts = [h for h in hosts if matches_os(h)]

    if args.service:
        svc_filter = args.service.lower()
        hosts = [h for h in hosts if any(s['name'].lower() == svc_filter for s in h['services'])]

    print(f"DB nmap: {nmap_db.path}")
    if args.os_filter or args.service:
        filtri = []
        if args.os_filter:
            filtri.append(f"OS={args.os_filter}")
        if args.service:
            filtri.append(f"service={args.service}")
        print(f"Filtri: {', '.join(filtri)}")

    if not hosts:
        print("Nessun host trovato con i filtri specificati.")
        return

    print(f"Host trovati: {len(hosts)}\n")

    # Calcola larghezze colonne
    col_ip = max(15, max(len(h['ip']) for h in hosts) + 1)
    col_mac = 19
    col_vendor = min(20, max((len(h['vendor']) for h in hosts if h['vendor']), default=6) + 1)
    col_host = min(28, max((len(h['hostname']) for h in hosts if h['hostname']), default=8) + 1)

    fmt = f"{{:<{col_ip}}} {{:<{col_mac}}} {{:<{col_vendor}}} {{:<{col_host}}} {{}}"
    sep = '-' * (col_ip + col_mac + col_vendor + col_host + 42)

    print(fmt.format('IP', 'MAC', 'Vendor', 'Hostname', 'OS'))
    print(sep)

    for h in hosts:
        vendor_str = (h['vendor'] or '')[:col_vendor - 1]
        hostname_str = (h['hostname'] or '')[:col_host - 1]
        os_str = (h['os'] or '')[:50]
        print(fmt.format(h['ip'], h['mac'] or '', vendor_str, hostname_str, os_str))


# --- Parser ---

def build_parser():
    R = argparse.RawDescriptionHelpFormatter

    parser = argparse.ArgumentParser(
        prog='netaudit',
        description='Tool di diagnostica e gestione switch Aruba',
        formatter_class=R,
        epilog=textwrap.dedent("""\
            lettura (sola lettura, nessuna modifica):
              diagnose                        diagnosi completa, salva report su file
              config                          running-config completa
              vlans                           lista tutte le VLAN
              vlan <id>                       dettaglio VLAN specifica
              stp                             Spanning Tree completo
              stp check                       analisi STP: TC count, porte blocking, root bridge
              ports                           stato porte (interface brief)
              macs [--port P] [--vlan V]      tabella MAC, filtrabile per porta o VLAN
              neighbors                       vicini LLDP (topologia)
              logs                            log di sistema
              port-names                      nomi/commenti configurati su ogni porta

            modifica (mostrano preview e chiedono conferma; usare --yes per bypassare):
              vlan create <id> <nome>         crea VLAN
              vlan delete <id>                elimina VLAN
              port access   <porta> <vlan>    imposta porta in access mode (untagged)
              port tag      <porta> <vlan>    aggiunge porta come tagged
              port untag    <porta> <vlan>    rimuove porta da tagged
              port set-name <porta> "<nome>"  imposta nome ("" per rimuoverlo)
              save                            salva configurazione (write memory)

            nmap (nessuna connessione switch):
              inventory [--os win|linux|other] [--service <nome>] [--list-services]
                                              inventario host attivi dal DB nmap

            nmap + switch:
              port find <ip|hostname|mac>     trova su quale porta è connesso un host
              macs                            tabella MAC arricchita con hostname nmap

            esempi:
              netaudit --switch centro_stella vlans
              netaudit --switch centro_stella macs --port 2/14
              netaudit --switch centro_stella port find 10.168.0.3
              netaudit --switch centro_stella port find DESKTOP-2G07OBV
              netaudit inventory
              netaudit inventory --os WIN
              netaudit inventory --service rdp
              netaudit --host 10.168.13.100 --user admin --password secret vlans
        """),
    )
    parser.add_argument('--switch', metavar='NOME',
                        help='Nome switch da switches.yaml')
    parser.add_argument('--host', metavar='IP',
                        help='IP/hostname switch (alternativa a --switch)')
    parser.add_argument('--user', metavar='USER', help='Username SSH')
    parser.add_argument('--password', metavar='PASS', help='Password SSH')
    parser.add_argument('--yes', action='store_true',
                        help='Bypassa conferma interattiva (per automazione/LLM)')
    parser.add_argument('--nmap-db', metavar='PATH', dest='nmap_db',
                        help='Percorso al file XML nmap (default: auto-detect map_rete*.xml)')

    sub = parser.add_subparsers(dest='cmd', metavar='COMANDO')
    sub.required = True

    sub.add_parser('diagnose', formatter_class=R,
                   help='Diagnosi completa — salva report con timestamp su file',
                   description='Esegue tutti i comandi di lettura e salva il report in un file\n'
                               'diagnose_<hostname>_<timestamp>.txt nella directory corrente.')

    sub.add_parser('config', formatter_class=R,
                   help='Mostra running-config completa',
                   description='Esegue "show running-config" e stampa l\'output.')

    sub.add_parser('vlans', formatter_class=R,
                   help='Elenca tutte le VLAN configurate',
                   description='Esegue "show vlan" e stampa la lista di tutte le VLAN.')

    sub.add_parser('vlan', formatter_class=R,
                   help='Mostra o gestisce una VLAN',
                   description=VLAN_USAGE,
                   ).add_argument('vlan_args', nargs='*', metavar='ARGS',
                                  help='id | create <id> <nome> | delete <id>')

    stp_p = sub.add_parser('stp', formatter_class=R,
                            help='Spanning Tree Protocol',
                            description=textwrap.dedent("""\
                                Mostra o analizza lo Spanning Tree (MSTP).

                                uso:
                                  netaudit stp          output completo di "show spanning-tree"
                                  netaudit stp check    analisi automatica: segnala TC count elevato,
                                                        porte in Blocking/Discarding, info root bridge"""))
    stp_p.add_argument('stp_args', nargs='*', metavar='ARGS',
                       help='[check]')

    sub.add_parser('ports', formatter_class=R,
                   help='Stato delle porte',
                   description='Esegue "show interface brief": stato, velocità, modalità di ogni porta.')

    macs_p = sub.add_parser('macs', formatter_class=R,
                             help='Tabella MAC address (arricchita con hostname nmap se disponibile)',
                             description=textwrap.dedent("""\
                                 Mostra la tabella MAC address dello switch.
                                 Se il DB nmap è disponibile, aggiunge una colonna Hostname.

                                 uso:
                                   netaudit macs                        tutta la tabella
                                   netaudit macs --port 1/3             MAC appresi sulla porta 1/3
                                   netaudit macs --vlan 2               MAC nella VLAN 2
                                   netaudit macs --port 1/3 --vlan 2   combinato"""))
    macs_p.add_argument('--port', metavar='PORTA', help='Filtra per porta (es. 1/3, 2/A1)')
    macs_p.add_argument('--vlan', metavar='VLAN', help='Filtra per VLAN (es. 2)')

    pn = sub.add_parser('port-names', formatter_class=R,
                        help='Mostra i nomi/commenti delle porte',
                        description=textwrap.dedent("""\
                            Mostra i nomi/commenti configurati sulle porte.

                            uso:
                              netaudit port-names             lista tutte le porte
                              netaudit port-names 2/24        mostra solo la porta 2/24"""))
    pn.add_argument('port', nargs='?', default=None, metavar='PORTA',
                    help='Porta specifica (opzionale, es. 2/24)')

    sub.add_parser('neighbors', formatter_class=R,
                   help='Vicini LLDP',
                   description='Esegue "show lldp info remote-device": mostra i dispositivi\n'
                               'connessi rilevati via LLDP (switch, AP, ecc.).')

    sub.add_parser('logs', formatter_class=R,
                   help='Log di sistema',
                   description='Esegue "show log -r": log di sistema in ordine cronologico inverso.')

    sub.add_parser('port', formatter_class=R,
                   help='Configura porta o cerca host per porta',
                   description=PORT_USAGE,
                   ).add_argument('port_args', nargs='*', metavar='ARGS',
                                  help='access|tag|untag|set-name <porta> <vlan>  oppure  find <ip|hostname|mac>')

    sub.add_parser('save', formatter_class=R,
                   help='Salva configurazione (write memory)',
                   description='Esegue "write memory" per rendere permanente la configurazione corrente.\n'
                               'Chiede conferma prima di procedere.')

    traverse_p = sub.add_parser('traverse', formatter_class=R,
                                 help='[Futuro] Traversata topologia multi-switch via LLDP',
                                 description='Discovery automatico della topologia di rete partendo\n'
                                             'da uno switch e seguendo i vicini LLDP. Non ancora implementato.')
    traverse_p.add_argument('--start', metavar='SWITCH', help='Switch di partenza (default: quello specificato)')
    traverse_p.add_argument('--depth', type=int, default=2, metavar='N',
                             help='Profondita\' di discovery (default: 2)')

    inv_p = sub.add_parser('inventory', formatter_class=R,
                            help='Inventario host attivi dal DB nmap (nessuna connessione switch)',
                            description=INVENTORY_USAGE)
    inv_p.add_argument('--os', dest='os_filter', metavar='OS',
                       choices=['win', 'linux', 'other'],
                       help='Filtra per OS: win, linux, other')
    inv_p.add_argument('--service', metavar='SVC',
                       help='Filtra per servizio aperto (es. ssh, rdp, smb, snmp)')
    inv_p.add_argument('--list-services', action='store_true',
                       help='Elenca tutti i servizi aperti nel DB nmap con conteggio host')

    return parser


COMMANDS = {
    'diagnose': cmd_diagnose,
    'config': cmd_config,
    'vlans': cmd_vlans,
    'vlan': cmd_vlan,
    'stp': cmd_stp,
    'ports': cmd_ports,
    'port-names': cmd_port_names,
    'macs': cmd_macs,
    'neighbors': cmd_neighbors,
    'logs': cmd_logs,
    'port': cmd_port,
    'save': cmd_save,
    'traverse': cmd_traverse,
    'inventory': cmd_inventory,
}

# Comandi che non richiedono connessione switch
SWITCH_NOT_REQUIRED = {'inventory'}


def validate_args(args):
    """Valida gli argomenti prima di aprire la connessione SSH."""
    if args.cmd == 'vlan':
        vlan_args = args.vlan_args
        if not vlan_args:
            print(VLAN_USAGE, file=sys.stderr)
            sys.exit(1)
        if vlan_args[0] in ('create', 'rename') and len(vlan_args) < 3:
            print(f"Errore: 'vlan {vlan_args[0]}' richiede <id> e <nome>\n\n{VLAN_USAGE}", file=sys.stderr)
            sys.exit(1)
        if vlan_args[0] == 'delete' and len(vlan_args) < 2:
            print(f"Errore: 'vlan delete' richiede <id>\n\n{VLAN_USAGE}", file=sys.stderr)
            sys.exit(1)

    if args.cmd == 'port':
        port_args = args.port_args
        if not port_args:
            print(PORT_USAGE, file=sys.stderr)
            sys.exit(1)
        if port_args[0] not in ('access', 'tag', 'untag', 'set-name', 'find'):
            print(f"Errore: sottocomando '{port_args[0]}' non riconosciuto\n\n{PORT_USAGE}", file=sys.stderr)
            sys.exit(1)
        if port_args[0] == 'find':
            if len(port_args) < 2:
                print(f"Errore: 'port find' richiede <ip|hostname|mac>\n\n{PORT_USAGE}", file=sys.stderr)
                sys.exit(1)
        elif len(port_args) < 3:
            print(f"Errore: 'port {port_args[0]}' richiede <porta> e <argomento>\n\n{PORT_USAGE}", file=sys.stderr)
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

    print(f"Connessione a {sw_config['host']}...")
    try:
        with Switch(**sw_config) as sw:
            print(f"Connesso a {sw.hostname}\n")
            handler(sw, args)
    except ConnectionError as e:
        print(f"Errore di connessione: {e}")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\nInterrotto dall'utente.")
        sys.exit(1)


if __name__ == '__main__':
    main()

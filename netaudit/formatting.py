"""Shared output rendering: aligned text tables, CSV, and MAC-table enrichment.

The column-width arithmetic used to be copy-pasted into every command that
printed a table; it lives here once instead.
"""

import csv
import io
import re

from netaudit.nmap_parser import NmapDB, normalize_mac

#: Aruba/ProCurve MAC table row, e.g. "  0001c0-17da89     1/23    1"
#: The MAC is 12 hex digits split by a SINGLE dash (xxxxxx-xxxxxx), unlike the
#: Comware/Cisco xxxx-xxxx-xxxx form.
MAC_ROW_RE = re.compile(r'^\s+([0-9a-f]{6}-[0-9a-f]{6})\s+(\S+)\s+(\d+)', re.IGNORECASE)

MAC_COLUMNS = ('MAC Address', 'Port', 'VLAN', 'IP', 'Hostname', 'Vendor', 'OS')


def render_table(headers, rows, indent='', min_widths=None, max_widths=None):
    """Render an aligned fixed-width text table.

    Column widths fit their content, bounded below by min_widths and above by
    max_widths (either may be None, or contain None per column).
    """
    n = len(headers)
    mins = list(min_widths or [0] * n)
    maxs = list(max_widths or [None] * n)

    widths = []
    for i, header in enumerate(headers):
        width = max([len(header), mins[i]] + [len(str(r[i])) for r in rows])
        if maxs[i]:
            width = min(width, maxs[i])
        widths.append(width)

    def line(cells):
        return (indent + ' '.join(str(c)[:w].ljust(w) for c, w in zip(cells, widths))).rstrip()

    out = [line(headers), indent + ' '.join('-' * w for w in widths)]
    out.extend(line(r) for r in rows)
    return '\n'.join(out)


def render_csv(headers, rows):
    """Render rows as CSV text (no trailing newline)."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(headers)
    writer.writerows(rows)
    return buf.getvalue().strip()


def parse_mac_table(raw):
    """Split a raw `show mac-address` output into (preamble lines, parsed rows).

    Each row is a dict with mac / port / vlan. Header and separator lines are
    dropped so the caller can render its own table.
    """
    preamble = []
    rows = []
    in_data = False

    for line in raw.splitlines():
        if re.search(r'MAC\s+Address', line, re.IGNORECASE):
            in_data = True
            continue
        if re.match(r'\s*-{5,}', line):
            continue
        match = MAC_ROW_RE.match(line)
        if match and in_data:
            rows.append({'mac': match.group(1), 'port': match.group(2), 'vlan': match.group(3)})
        elif not in_data:
            preamble.append(line)

    return preamble, rows


def lookup_host(nmap_db, mac):
    """Return the nmap host record for a switch-formatted MAC, or None."""
    if not nmap_db:
        return None
    normalized = normalize_mac(mac)
    return nmap_db.host_by_mac(normalized) if normalized else None


def enrich_mac_table(raw, nmap_db, show_services=False, as_csv=False):
    """Re-render a raw MAC table with IP/hostname/vendor/OS from the nmap DB.

    Works with nmap_db=None: the extra columns are simply empty, which is what
    makes `macs --csv` usable without a scan loaded.
    """
    preamble, parsed = parse_mac_table(raw)

    headers = list(MAC_COLUMNS)
    if show_services:
        headers.append('Services')

    rows = []
    for row in parsed:
        host = lookup_host(nmap_db, row['mac'])
        cells = [
            row['mac'], row['port'], row['vlan'],
            host['ip'] if host else '',
            host['hostname'] if host else '',
            host['vendor'] if host else '',
            host['os'] if host else '',
        ]
        if show_services:
            cells.append(NmapDB.format_services(host) if host else '')
        rows.append(cells)

    if as_csv:
        return render_csv(headers, rows)

    min_widths = [18, 10, 6, 16, 24, 20, 4] + ([10] if show_services else [])
    table = render_table(headers, rows, indent='  ', min_widths=min_widths)
    return '\n'.join(preamble + [table])

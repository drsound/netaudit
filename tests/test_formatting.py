import textwrap

from netaudit.formatting import (
    enrich_mac_table,
    parse_mac_table,
    render_csv,
    render_table,
)

# Aruba "show mac-address" output: the MAC is xxxxxx-xxxxxx, a single dash.
RAW_MAC_TABLE = textwrap.dedent("""\
     Status and Counters - Port Address Table

      MAC Address   Port                    VLAN
      ------------- ----------------------- ----
      0001c0-17da89 1/23                    1
      aabbcc-ddeeff 2/A1                    10
      001122-334455 1/5                     1
    """)


def test_parse_mac_table_extracts_rows_and_preamble():
    preamble, rows = parse_mac_table(RAW_MAC_TABLE)

    assert any('Status and Counters' in line for line in preamble)
    assert [r['mac'] for r in rows] == ['0001c0-17da89', 'aabbcc-ddeeff', '001122-334455']
    assert [r['port'] for r in rows] == ['1/23', '2/A1', '1/5']
    assert [r['vlan'] for r in rows] == ['1', '10', '1']


def test_parse_mac_table_ignores_comware_style_macs():
    # xxxx-xxxx-xxxx is a different vendor format and must not be misparsed as
    # an Aruba row.
    raw = "  MAC Address   Port  VLAN\n  0001-c017-da89 1/23  1\n"
    _, rows = parse_mac_table(raw)
    assert rows == []


def test_enrich_mac_table_adds_nmap_columns(nmap_db):
    out = enrich_mac_table(RAW_MAC_TABLE, nmap_db)

    assert 'DESKTOP-A' in out
    assert '10.0.0.5' in out
    assert 'Synology' in out
    # A MAC the DB does not know still gets a row, just with blank columns.
    assert '001122-334455' in out


def test_enrich_mac_table_csv_has_one_header_and_a_row_per_mac(nmap_db):
    out = enrich_mac_table(RAW_MAC_TABLE, nmap_db, as_csv=True)
    lines = out.splitlines()

    assert lines[0] == 'MAC Address,Port,VLAN,IP,Hostname,Vendor,OS'
    assert len(lines) == 4
    assert lines[1].startswith('0001c0-17da89,1/23,1,10.0.0.5,DESKTOP-A')


def test_enrich_mac_table_csv_works_without_nmap_db():
    out = enrich_mac_table(RAW_MAC_TABLE, None, as_csv=True)
    lines = out.splitlines()

    assert len(lines) == 4
    assert lines[1] == '0001c0-17da89,1/23,1,,,,'


def test_enrich_mac_table_services_column_is_opt_in(nmap_db):
    without = enrich_mac_table(RAW_MAC_TABLE, nmap_db, as_csv=True)
    with_services = enrich_mac_table(RAW_MAC_TABLE, nmap_db, show_services=True, as_csv=True)

    assert 'Services' not in without
    assert with_services.splitlines()[0].endswith(',Services')
    assert '22/tcp(ssh), 80/tcp(http)' in with_services


def test_render_table_pads_to_content_width():
    out = render_table(['A', 'Bee'], [['xxxxx', 'y']])
    header, sep, row = out.splitlines()

    assert header == 'A     Bee'
    assert sep == '----- ---'
    assert row == 'xxxxx y'


def test_render_table_respects_min_and_max_widths():
    out = render_table(['A'], [['abcdefgh']], min_widths=[2], max_widths=[4])
    assert out.splitlines()[2] == 'abcd'

    out = render_table(['A'], [['x']], min_widths=[6])
    assert out.splitlines()[1] == '------'


def test_render_csv_quotes_embedded_commas():
    out = render_csv(['Name'], [['a,b']])
    assert out.splitlines()[1] == '"a,b"'

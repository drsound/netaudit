"""Parser tests for diagnostics.py.

The fixtures reproduce the exact column layout and notation of Aruba-OS /
ProCurve output (MAC as xxxxxx-xxxxxx, trailing padding, the "Mode" column
carrying speed+duplex as one word). Identifiers are anonymized; the shape is
what matters, because every bug these tests cover was a parser that assumed a
shape the switches do not produce.
"""

import textwrap
from datetime import datetime, timedelta

import pytest

from netaudit import diagnostics

# "show spanning-tree" — note the trailing spaces, which the switch really emits.
STP_SUMMARY = textwrap.dedent("""\

     Multiple Spanning Tree (MST) Information

      STP Enabled   : Yes
      Force Version : MSTP-operation
      IST Mapped VLANs : 7-4094
      Switch MAC Address : 3c4d5e-6f7081\x20\x20\x20\x20
      Switch Priority    : 16384

      CST Root MAC Address : 3c4d5e-9a0b1c\x20\x20\x20\x20
      CST Root Priority    : 0
    """)

# "show spanning-tree detail" — one port block.
STP_DETAIL = textwrap.dedent("""\

     Status and Counters - CST Port(s) Detailed Information

      Port                      : 1/1\x20\x20
      Status                    : Up\x20\x20
      AdminEdgePort             : Yes\x20
      OperEdgePort              : No\x20
    """)


class FakeSwitch:
    hostname = 'core-sw'
    host = '10.0.0.1'
    meta = {}

    def __init__(self, outputs):
        self._outputs = outputs

    def run(self, cmd, timeout=30):
        return self._outputs.get(cmd, '')


def stp_switch(summary=STP_SUMMARY, detail=STP_DETAIL):
    return FakeSwitch({'show spanning-tree': summary, 'show spanning-tree detail': detail})


# --- root bridge check -------------------------------------------------------

@pytest.mark.parametrize('expected', [
    '3c:4d:5e:9a:0b:1c',   # the form switches.yaml.example and the README document
    '3c4d5e-9a0b1c',       # the form the switch itself prints
    '3C4D5E9A0B1C',        # bare, upper case
])
def test_root_bridge_match_is_notation_independent(expected):
    """A raw string compare meant the documented colon notation NEVER matched
    the Aruba notation the switch prints, so every run warned about a root
    bridge mismatch that did not exist."""
    out = diagnostics.get_stp_detail(stp_switch(), expected_root_mac=expected)

    assert 'matches the expected root bridge' in out
    assert 'does NOT match' not in out


def test_root_bridge_mismatch_is_still_reported():
    out = diagnostics.get_stp_detail(stp_switch(), expected_root_mac='aa:bb:cc:dd:ee:ff')

    assert 'does NOT match' in out
    assert '3c4d5e-9a0b1c' in out


def test_unparseable_expected_root_mac_is_called_out_not_reported_as_a_mismatch():
    out = diagnostics.get_stp_detail(stp_switch(), expected_root_mac='not-a-mac')

    assert 'not a valid MAC address' in out
    assert 'does NOT match' not in out


def test_without_expected_root_mac_a_non_root_switch_is_noticed():
    out = diagnostics.get_stp_detail(stp_switch())

    assert 'Switch is not root' in out


def test_without_expected_root_mac_a_root_switch_is_recognized():
    summary = STP_SUMMARY.replace('CST Root MAC Address : 3c4d5e-9a0b1c',
                                  'CST Root MAC Address : 3c4d5e-6f7081')
    out = diagnostics.get_stp_detail(stp_switch(summary=summary))

    assert 'This switch IS the Root Bridge' in out


def test_missing_switch_mac_does_not_claim_the_switch_is_root():
    summary = STP_SUMMARY.replace('Switch MAC Address : 3c4d5e-6f7081', '')
    out = diagnostics.get_stp_detail(stp_switch(summary=summary))

    assert 'IS the Root Bridge' not in out
    assert 'cannot tell whether this switch is the root' in out


def test_stp_disabled_is_critical():
    summary = STP_SUMMARY.replace('STP Enabled   : Yes', 'STP Enabled   : No')
    out = diagnostics.get_stp_detail(stp_switch(summary=summary))

    assert 'CRITICAL: STP is disabled' in out


# --- physical checks ---------------------------------------------------------

#: "show interface brief". The Mode column is speed+duplex as ONE word.
INTERFACE_BRIEF = textwrap.dedent("""\

     Status and Counters - Port Status

                              | Intrusion                           MDI  Flow Bcast
      Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit
      ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----
      1/1          100/1000T  | No        Yes     Up     1000FDx    MDI  off  0\x20\x20\x20\x20
      1/2          100/1000T  | No        Yes     Up     100FDx     MDIX off  0\x20\x20\x20\x20
      1/3          100/1000T  | No        Yes     Up     10HDx      MDI  off  0\x20\x20\x20\x20
      1/4          100/1000T  | No        Yes     Down   1000FDx    Auto off  0\x20\x20\x20\x20
    """)


def physical_switch(brief=INTERFACE_BRIEF, transceiver='Invalid input: transceiver'):
    return FakeSwitch({'show interface brief': brief,
                       'show interfaces transceiver detail': transceiver})


def test_half_duplex_is_a_warning():
    out = diagnostics.check_physical(physical_switch())

    assert 'Port 1/3: Operating in Half-Duplex (10HDx)!' in out


def test_below_gigabit_ports_are_reported():
    """The old test was `speed_mode in ('10', '100')`, but the Mode column is
    always a word like '100FDx' — so this branch could never fire."""
    out = diagnostics.check_physical(physical_switch())

    assert 'Port 1/2: Operating below gigabit (100FDx)' in out


def test_gigabit_ports_are_not_reported_as_slow():
    out = diagnostics.check_physical(physical_switch())

    assert '1/1: Operating below gigabit' not in out


def test_down_ports_are_not_analyzed_for_speed():
    out = diagnostics.check_physical(physical_switch())

    assert '1/4: Operating' not in out


# --- log correlation ---------------------------------------------------------

def build_log(config_changes=1, outages_per_change=3):
    """A log where a flapping port goes off-line repeatedly after each config change."""
    now = datetime.now()
    lines = []
    for i in range(config_changes):
        change = now - timedelta(minutes=30 * i)
        lines.append(f"I {change:%m/%d/%y %H:%M:%S} 00001 mgr: configuration changed")
        for j in range(outages_per_change):
            lines.append(f"I {change + timedelta(seconds=10 + j):%m/%d/%y %H:%M:%S}"
                         f" 00076 ports: port 1/A1 is now off-line")
            lines.append(f"I {change + timedelta(seconds=12 + j):%m/%d/%y %H:%M:%S}"
                         f" 00076 ports: port 1/A1 is now on-line")
    return '\n'.join(lines)


def log_switch(log):
    return FakeSwitch({'show log -r': log})


def test_correlation_reports_one_alert_per_config_change():
    """One line per (port, config change) — not one per off-line event. A
    flapping port used to emit an alert for every outage in the window, burying
    the rest of the report."""
    out = diagnostics.analyze_logs(log_switch(build_log(config_changes=2, outages_per_change=3)))

    assert out.count('CORRELATION ALERT') == 2


def test_correlation_reports_the_first_outage_and_counts_the_rest():
    out = diagnostics.analyze_logs(log_switch(build_log(config_changes=1, outages_per_change=3)))

    assert 'went off-line 10s after configuration change' in out
    assert '(+2 more outage(s) in the same window)' in out


def test_a_single_outage_carries_no_suffix():
    out = diagnostics.analyze_logs(log_switch(build_log(config_changes=1, outages_per_change=1)))

    assert out.count('CORRELATION ALERT') == 1
    assert 'more outage(s)' not in out


def test_flapping_port_is_reported():
    out = diagnostics.analyze_logs(log_switch(build_log(config_changes=1, outages_per_change=3)))

    assert 'Port 1/A1 is FLAPPING!' in out


def test_quiet_logs_report_nothing_suspicious():
    out = diagnostics.analyze_logs(log_switch("I 08/07/26 10:00:00 00076 ports: port 1/1 is now on-line"))

    assert 'No critical events or suspicious patterns found' in out


# --- topology change counter -------------------------------------------------

def test_topology_change_count_survives_thousands_separators():
    """The switch groups thousands ("530,618"); a bare \\d+ stopped at the comma
    and reported 530, under-stating the count by three orders of magnitude."""
    summary = STP_SUMMARY + "\n      Topology Change Count  : 530,618\n"
    out = diagnostics.check_stp_health(FakeSwitch({'show spanning-tree': summary}))

    assert 'High Topology Change Count: 530618' in out
    assert 'Count: 530 ' not in out


def test_topology_change_count_below_threshold_is_informational():
    summary = STP_SUMMARY + "\n      Topology Change Count  : 12\n"
    out = diagnostics.check_stp_health(FakeSwitch({'show spanning-tree': summary}))

    assert 'Topology Change Count: 12' in out
    assert 'WARNING: High Topology Change Count' not in out


# --- STP guard flags ---------------------------------------------------------

#: A port block using the spacing the switches actually emit.
STP_DETAIL_GUARDS = textwrap.dedent("""\

      Port                      : 1/20\x20\x20
      Status                    : Up\x20\x20
      BPDU Protection           : No\x20
      BPDU Filtering            : No\x20
      PVST Protection           : No\x20
      PVST Filtering            : No\x20
      Root Guard                : Yes
      Loop Guard                : Yes
      TCN Guard                 : No\x20
      AdminEdgePort             : No\x20\x20
      OperEdgePort              : No\x20
    """)


def test_spaced_guard_labels_are_parsed():
    """The table held "RootGuard"/"TCNGuard"/"LoopGuard"/"BPDUProtection", but
    the switches print those labels WITH spaces — so four of the six flags never
    matched and the active-guards report was permanently empty."""
    out = diagnostics.get_stp_detail(stp_switch(detail=STP_DETAIL_GUARDS))

    assert 'Port 1/20 active guards: Root Guard, Loop Guard' in out


def test_compact_guard_labels_are_still_parsed():
    """Firmware revisions differ; matching ignores whitespace so both spellings work."""
    detail = (STP_DETAIL_GUARDS.replace('Root Guard    ', 'RootGuard     ')
                               .replace('Loop Guard    ', 'LoopGuard     '))
    out = diagnostics.get_stp_detail(stp_switch(detail=detail))

    assert 'Port 1/20 active guards: Root Guard, Loop Guard' in out


def test_guards_set_to_no_are_not_reported():
    out = diagnostics.get_stp_detail(stp_switch(detail=STP_DETAIL_GUARDS))

    assert 'TCN Guard' not in out
    assert 'PVST' not in out


def test_admin_edge_without_oper_edge_is_a_warning():
    out = diagnostics.get_stp_detail(stp_switch())

    assert 'Port 1/1: Configured as Edge (Admin) but operating as Non-Edge' in out


# --- SFP DDM -----------------------------------------------------------------

#: "show interfaces transceiver detail" — the real multi-line block layout.
TRANSCEIVER = textwrap.dedent("""\
    Transceiver in 1/21
       Interface Index    : 21\x20\x20
       Type               : 1000SX
       Model              : J4858D
       Diagnostic Support : DOM
       Serial Number      : CN00TEST01

     Status
       Temperature : 30.562C
       Voltage     : 3.2500V
       Tx Bias     : 3.420mA
       Tx Power    : 0.3324mW, -4.783dBm
       Rx Power    : 0.2728mW, -5.641dBm

    Transceiver in 2/A1
       Interface Index    : 79
       Type               : SFP+SR
       Model              : J9150D
       Diagnostic Support : DOM
       Serial Number      : CN00TEST02

     Status
       Temperature : 33.976C
       Voltage     : 3.2531V
       Tx Bias     : 5.974mA
       Tx Power    : 0.5335mW, -2.729dBm
       Rx Power    : 0.4795mW, -3.192dBm
    """)


def sfp_switch(transceiver=TRANSCEIVER, config=''):
    return FakeSwitch({'show interface brief': INTERFACE_BRIEF,
                       'show interfaces transceiver detail': transceiver,
                       'show running-config': config})


def test_block_format_transceivers_are_read():
    """The parser expected one tabular line per SFP, a layout this hardware
    never emits, so a switch with five live optics reported none."""
    out = diagnostics.check_physical(sfp_switch())

    assert 'SFP on 1/21 (1000SX): Tx=-4.783dBm, Rx=-5.641dBm, Temp=30.562C, Vcc=3.25V' in out
    assert 'SFP on 2/A1 (SFP+SR)' in out
    assert 'No active SFP physical diagnostics found' not in out


def test_healthy_optics_raise_no_warning():
    out = diagnostics.check_physical(sfp_switch())

    assert 'sensitivity floor' not in out
    assert 'exceeds' not in out


def test_low_receive_power_is_a_warning():
    weak = TRANSCEIVER.replace('Rx Power    : 0.2728mW, -5.641dBm',
                               'Rx Power    : 0.0043mW, -23.665dBm')
    out = diagnostics.check_physical(sfp_switch(transceiver=weak))

    assert 'Port 1/21: SFP receive power -23.665dBm is below the -17.0dBm sensitivity floor' in out


def test_overheating_optic_is_a_warning():
    hot = TRANSCEIVER.replace('Temperature : 30.562C', 'Temperature : 78.100C')
    out = diagnostics.check_physical(sfp_switch(transceiver=hot))

    assert 'Port 1/21: SFP temperature 78.1C exceeds 70.0C!' in out


def test_out_of_range_supply_voltage_is_a_warning():
    bad = TRANSCEIVER.replace('Voltage     : 3.2500V', 'Voltage     : 2.8100V')
    out = diagnostics.check_physical(sfp_switch(transceiver=bad))

    assert 'Port 1/21: SFP supply voltage 2.81V is outside 3.0-3.6V!' in out


def test_transceiver_without_ddm_is_listed_not_dropped():
    plain = textwrap.dedent("""\
        Transceiver in 1/21
           Type               : 1000LX
           Model              : J4859C
           Diagnostic Support : none
        """)
    out = diagnostics.check_physical(sfp_switch(transceiver=plain))

    assert 'SFP on 1/21: 1000LX (J4859C), no DDM data' in out


def test_switch_without_transceiver_support_says_so():
    out = diagnostics.check_physical(sfp_switch(transceiver='Invalid input: transceiver'))

    assert 'not supported on this switch' in out


# --- pinned port settings ----------------------------------------------------

def test_pinned_speed_duplex_is_reported():
    config = textwrap.dedent("""\
        interface 7
           speed-duplex 100-half
           exit
        interface 8
           name "Printer"
           exit
        """)
    out = diagnostics.check_physical(sfp_switch(config=config))

    assert 'Port 7: speed-duplex pinned to 100-half (auto-negotiation disabled)' in out
    assert 'Port 8' not in out


def test_pinned_mdix_mode_is_reported():
    config = "interface 1/5\n   mdix-mode mdi\n   exit\n"
    out = diagnostics.check_physical(sfp_switch(config=config))

    assert 'Port 1/5: mdix-mode pinned to mdi (auto-negotiation disabled)' in out


def test_negotiated_mdi_mode_is_never_reported_as_an_anomaly():
    """The MDI column of `show interface brief` shows what a link NEGOTIATED,
    so reading it flagged nearly every connected port. Only running-config,
    which records non-defaults only, can reveal a pinned mode."""
    out = diagnostics.check_physical(sfp_switch(config=''))

    assert 'MDI' not in out
    assert 'pinned' not in out

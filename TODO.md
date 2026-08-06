# TODO — multi-vendor support

Everything in `diagnostics.py` sends ArubaOS-Switch / ProCurve commands and
parses ArubaOS-Switch / ProCurve output. On any other platform the commands
either do not exist or return a different layout, and the parsers quietly
return nothing. This file is the plan for fixing that.

All command availability and every output sample below was **verified against
live hardware in August 2026**, not taken from vendor documentation. Sample
MACs, hostnames and serials are anonymized; the column layout, notation and
spacing are reproduced exactly, because that is what the parsers depend on.

---

## 1. State of play

Three CLI dialects are in scope. They are not variations of one syntax — the
command names, the port naming and the MAC notation all differ.

| dialect | `device_type` | verified on | share of a real estate |
|---|---|---|---|
| ArubaOS-Switch / ProCurve | `aruba_osswitch`, `hp_procurve` | Aruba 2930M, 2530, HP 2530 | 7 of 10 switches |
| ArubaOS-CX | `aruba_aoscx` | Aruba 6100 24G, PL.10.06 | 2 of 10 |
| FiberStore FSOS | `fiberstore_fsosv2` | FS S3400-24T4FP, FSOS 2.2.0D | 1 of 10 |

Two traps worth knowing before starting:

- **The model name does not tell you the dialect.** An "Aruba 6100" is CX; an
  "Aruba 2530" is AOS-Switch. Both are "Aruba". Check `show version`: CX prints
  `ArubaOS-CX`, AOS-Switch prints an `Image stamp:` line.
- **`fiberstore_fsos` fails authentication** on the S3400; only
  `fiberstore_fsosv2` connects. A wrong `device_type` does not fail at connect
  time — netmiko attaches happily and then every command misses, which reads
  exactly like a broken parser.

---

## 2. Verified command map

`YES` / `NO` is whether the command exists on that platform. Blank cells are
the same command as the AOS-Switch column.

| purpose | ArubaOS-Switch | ArubaOS-CX | FSOS |
|---|---|---|---|
| running config | `show running-config` | YES | YES |
| VLANs | `show vlan` | YES | YES |
| port status | `show interface brief` | YES | YES |
| port names | `show name` | **NO** → use the `Description` column of `show interface brief` | **NO** → same |
| MAC table | `show mac-address` | YES | **NO** → `show mac address-table` |
| LLDP | `show lldp info remote-device` | **NO** → `show lldp neighbor-info` | **NO** → `show lldp neighbors` (see note) |
| logs | `show log -r` | **NO** → `show logging -r` (or `show events -r`) | **NO** → `show logging` (see note) |
| STP | `show spanning-tree` | YES | YES |
| STP detail | `show spanning-tree detail` | YES (same output as above) | untested |
| SFP DDM | `show interfaces transceiver detail` | **NO** → `show interface transceiver detail` (singular) | **NO** — no working command found; tried `show transceiver`, `show interface transceiver` |

Notes on the two that need care:

- **FSOS LLDP** answers `LLDP is not enabled`. The command name is right, the
  feature is off on the device. Treat "protocol disabled" as distinct from
  "command unsupported" — the user can fix the first, not the second.
- **FSOS logs**: `show logging` prints only the logging *configuration*, and on
  the tested switch `Buffer logging: disabled`, so there is no retrievable log
  history at all. `log-audit` cannot work there until buffer logging is turned
  on. Say so rather than reporting "no events found".
- **CX logs are huge**: `show logging -r` returned **85,131 lines**. It needs a
  bound (`show logging -r | last N`, or a line cap in the caller) or `log-audit`
  will be unusable.

---

## 3. Output formats

### 3.1 `show interface brief`

**AOS-Switch** — `Mode` is speed+duplex as one word; `MDI Mode` is the
*negotiated* result and must not be read as configuration (see §6).

```
                          | Intrusion                           MDI  Flow Bcast
  Port         Type       | Alert     Enabled Status Mode       Mode Ctrl Limit
  ------------ ---------- + --------- ------- ------ ---------- ---- ---- -----
  1/1          100/1000T  | No        Yes     Up     1000FDx    MDI  off  0
```

**CX** — no duplex and no MDI column at all; speed is a bare number in Mb/s.
Carries the port description, which is what replaces `show name`.

```
Port      Native  Mode   Type           Enabled Status  Reason                 Speed   Description
          VLAN                                                                 (Mb/s)
--------------------------------------------------------------------------------------------------------------
1/1/1     1       access 1GbT           yes     up                             1000    --
1/1/3     1       access 1GbT           yes     down    Waiting for link       --      --
```

Note `--` for "no value" and a lowercase `up`/`down`. An empty description also
prints as `--`.

**FSOS** — description first, duplex and speed in separate columns.

```
Port    Description           Status    Vlan        Duplex   Speed    Type
g0/1                          up        1           full     100Mb    Giga-TX
g0/2                          down      1           auto     auto     Giga-TX
```

### 3.2 MAC table

Three different notations *and* three different column orders:

```
AOS-Switch   show mac-address          MAC Address / Port / VLAN
  0001c0-17da89 1/23                    1

CX           show mac-address          MAC Address / VLAN / Type / Port
  aa:bb:cc:11:22:33    1        dynamic                   1/1/27

FSOS         show mac address-table    Vlan / Mac Address / Type / Ports
  1<TAB>aabb.cc11.2233<TAB>  DYNAMIC    g0/24
```

The FSOS rows are **tab-separated**, not space-aligned. Do not assume columns
line up.

`normalize_mac()` in `nmap_parser.py` already handles all of these — dashes,
colons and dots, any case. It is the only piece of this work that is done.
Everything that compares MACs must go through it.

### 3.3 Spanning tree

**AOS-Switch** — `CST Root MAC Address : xxxxxx-xxxxxx`, plus a per-port block
with `Root Guard : No`-style flags. Already parsed.

**CX** — a completely different shape. No per-port guard block; port state lives
in a table.

```
Spanning tree status      : Enabled Protocol: MSTP

MST0
  Root ID    Priority   : 0
             MAC-Address: aa:bb:cc:11:22:33
  Bridge ID  Priority  : 32768
             MAC-Address: dd:ee:ff:44:55:66

Port         Role           State      Cost           Priority   Type             BPDU-Tx    BPDU-Rx    TCN-Tx     TCN-Rx
------------ -------------- ---------- -------------- ---------- ---------------- ---------- ---------- ---------- ----------
1/1/1        Designated     Forwarding 20000          128        P2P              26444855   0          0          0
1/1/3        Disabled       Blocking   20000          128        P2P              0          0          0          0
```

There is **no global "Topology Change Count"** on CX — TC is per port
(`TCN-Tx` / `TCN-Rx`). `check_stp_health` needs a different rule there, e.g. sum
or max across ports.

**FSOS** — RSTP, MAC in uppercase dotted form, long port names in the root block
(`GigaEthernet0/24`) but short ones in the MAC table (`g0/24`). Normalize.

```
Spanning tree enabled protocol RSTP(2004)

RSTP
  Root ID    Priority    0
             Address     AABB.CC11.2233
             Port        GigaEthernet0/24
             Cost        40000
  Bridge ID  Priority    32768
             Address     DDEE.FF44.5566
```

### 3.4 LLDP

**CX** `show lldp neighbor-info`:

```
LOCAL-PORT  CHASSIS-ID         PORT-ID                      PORT-DESC                    TTL      SYS-NAME
-----------------------------------------------------------------------------------------------------------
```

Different column names and no `|` separator, so the existing index-based parser
in `get_lldp_neighbors` will not transfer as is.

### 3.5 SFP DDM

CX uses the same block layout as AOS-Switch, with two differences: the model
field is `Product Number` (not `Model`), and **Rx Power comes before Tx Power**.
The existing `_parse_transceivers` is label-keyed, so it should mostly work —
but `_check_transceivers` reads `data.get('model')`, which is absent on CX.

```
Transceiver in 1/1/27
 Interface Name      : 1/1/27
 Type                : SFP+SR
 Product Number      : J9150D
 Serial Number       : XXXXXXXXXX

 Status
  Temperature : 26.7578C
  Voltage     : 3.2808V
  Tx Bias     : 6.0720mA
  Rx Power    : 0.4946mW, -3.06dBm
  Tx Power    : 0.4959mW, -3.05dBm
```

### 3.6 Logs

**AOS-Switch**: `I 03/08/26 11:34:16 00076 ports: port 1/A1 is now on-line`

**CX**: syslog style, ISO-8601 with timezone, pipe-delimited payload:

```
2026-08-06T22:56:41.108574+02:00 HOSTNAME hpe-restd[2647]: Event|4650|LOG_INFO|AMM|-|message text
```

`analyze_logs` parses the AOS-Switch form only — the timestamp regex, the module
field and the flap/config-change patterns all need a CX variant.

---

## 4. Proposed design

Keep it boring. Do not build a plugin system for three dialects.

1. **`netaudit/dialects.py`** — one table mapping a dialect key to its command
   strings:

   ```python
   DIALECTS = {
       'aos_switch': {'mac_table': 'show mac-address', 'logs': 'show log -r', ...},
       'aos_cx':     {'mac_table': 'show mac-address', 'logs': 'show logging -r', ...},
       'fsos':       {'mac_table': 'show mac address-table', 'logs': None, ...},
   }
   DEVICE_TYPE_TO_DIALECT = {
       'aruba_osswitch': 'aos_switch', 'hp_procurve': 'aos_switch',
       'aruba_aoscx': 'aos_cx', 'fiberstore_fsosv2': 'fsos', ...
   }
   ```

   `None` means "this platform has no equivalent" and is distinct from a missing
   key.

2. **`Switch` gains `.dialect`**, resolved from `device_type` at construction.
   Default to `aos_switch` for unknown types, and warn once — an unrecognised
   `device_type` should not silently behave like an Aruba.

3. **`diagnostics.py` functions take the command from the dialect table** rather
   than hardcoding it, and dispatch to a per-dialect parser where the layout
   differs.

4. **An unsupported command must be an explicit outcome**, never empty output:

   ```
   $ netaudit --switch r9_aruba port-names
   port-names is not available on ArubaOS-CX: the platform has no
   `show name`. Port descriptions are in `netaudit ports`.
   ```

   Same for a parser that does not exist yet for a dialect. Silent empty output
   is the bug this whole file exists to remove.

5. **Exit non-zero** on unsupported, so estate-wide scripting can tell the
   difference between "clean" and "never ran".

---

## 5. Task breakdown

Ordered so each step is independently shippable and testable.

- [ ] **T1 — dialect table and resolution.** `dialects.py`, `Switch.dialect`,
      warn on unknown `device_type`. No behaviour change for AOS-Switch.
      *Done when:* the existing 102 tests still pass and `Switch(device_type=...)`
      resolves all six `device_type` values used in the wild.

- [ ] **T2 — route commands through the table.** Replace the hardcoded strings
      in `diagnostics.py`. Raw-output commands (`config`, `vlans`, `ports`,
      `logs`, `neighbors`, `macs` without `--csv`) then work on all three.
      *Done when:* `vlans`, `ports`, `config` return real output on a CX and an
      FSOS switch; unsupported ones print the §4.4 message and exit 1.

- [ ] **T3 — MAC table parser per dialect.** Three notations, three column
      orders, tabs on FSOS. Unblocks `macs --csv`, `port find`, `port find
      --rogue` everywhere.
      *Done when:* `parse_mac_table` returns identical dicts for all three
      fixtures, and a MAC copied from any platform's output resolves through
      `port find`.

- [ ] **T4 — interface brief parser per dialect.** Unblocks `ports --csv` and
      the speed/duplex half of `physical-check`. Note CX has no duplex column,
      so the half-duplex check cannot apply there — say so rather than passing.
      Also wire the `Description` column into `port-names` for CX and FSOS.

- [ ] **T5 — STP parser for CX and FSOS.** The largest single piece. CX has no
      per-port guard block and no global TC counter; decide what `stp check`
      and `stp detail` mean there before writing the parser.

- [ ] **T6 — LLDP parser for CX.** Distinguish "not enabled" from "unsupported"
      on FSOS.

- [ ] **T7 — logs for CX.** New timestamp and module format; bound the output
      (85k lines). Report the FSOS buffer-disabled case explicitly.

- [ ] **T8 — SFP DDM for CX.** Should be close to free given the shared block
      layout; handle `Product Number` vs `Model`.

---

## 6. Things already established — do not re-derive

- `normalize_mac()` handles every notation seen. Use it for all MAC comparison.
- **The `MDI Mode` column of `show interface brief` is the negotiated result,
  not configuration.** Reading it produced 30 false positives on a 40-port
  switch. Pinned settings are only visible in `show running-config`
  (`speed-duplex`, `mdix-mode`), which records non-defaults only. Verified: the
  whole estate has zero pinned settings. Do not reintroduce the column check.
- AOS-Switch STP guard labels are spaced (`Root Guard`, not `RootGuard`) and
  vary by firmware. `_STP_FLAG_BY_LABEL` matches with whitespace stripped —
  keep that approach for new dialects.
- AOS-Switch counters use thousands separators (`530,618`). Strip commas before
  `int()`.
- `check_physical` reads the running-config; `--no-config` skips it. Measured
  cost is ~1s of a 4-6s run, dominated by SSH setup.

---

## 7. Testing

Unit tests only — no switch access required, and none of the fixtures may carry
real client data.

- Put per-dialect fixtures in `tests/fixtures/<dialect>_<command>.txt`,
  reproducing column layout, notation and trailing whitespace exactly.
  Anonymize MACs, hostnames, IPs and serials. Trailing spaces are significant:
  the AOS-Switch parsers anchor on leading whitespace.
- Every parser gets the same test applied to all three dialects, asserting they
  produce the **same structure** from different input. That is the property that
  makes the abstraction worth having.
- Add a test that an unknown `device_type` warns and falls back rather than
  silently behaving like an Aruba.
- `tests/test_diagnostics.py` is the model to follow: each test names the defect
  it prevents.

Live verification, when hardware is available, must stay **read-only** — the
estate is in production. `query`, `vlans`, `ports`, `macs`, `stp`, `neighbors`,
`logs`, `config`, `physical-check`, `port find` are all safe. Never
`vlan create/rename/delete`, `port access/tag/untag/set-name`, or `save`.

---

## 8. Out of scope here

Tracked separately, not part of the multi-vendor work: `--all` fan-out across
the inventory, snapshot/diff, `--json` output, meaningful exit codes for
`stp check` / `physical-check`, and finishing the `traverse` stub.

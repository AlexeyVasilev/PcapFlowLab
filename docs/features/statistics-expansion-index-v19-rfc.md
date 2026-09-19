# Statistics Expansion and Index Provenance v19 RFC

Status: Proposed.

Revision 18 remains the current implemented stable index revision. This RFC
freezes the intended revision 19 Statistics and provenance contract before
production implementation. It does not describe current runtime behavior unless
explicitly marked as current context.

Related current references:

- [Statistics, Reporting, and Large-Index Architecture RFC](statistics-reporting-index-rfc.md)
- [Index v16 Container RFC](index-v16-container-rfc.md)
- [Current State](../current-state.md)
- [Technical Documentation](../README.md)

## Purpose

Revision 19 is intended to add one coherent Statistics/index feature set:

- Flows by Duration.
- Flows by Data Size, bucketed by total original bytes.
- Capture-wide IP Fragmentation Statistics.
- Capture-import-settings provenance in a dedicated stable-container section.

This feature set extends the authoritative persisted Statistics data used by
Qt, Tauri, CLI, HTML, and Markdown reporting. It must preserve the existing
large-capture rule that Statistics can be served from index metadata without
source-capture reads.

## Flow Unit

User-visible `Flow` means the bidirectional conversation represented
internally by a `Connection`.

The directional internal `FlowV4` / `FlowV6` legs are not the unit for the new
whole-capture histograms.

Every new flow histogram bucket stores:

- `flow_count`
- `captured_byte_count`
- `original_byte_count`

All values are unsigned 64-bit-compatible counters. Captured/original bytes are
totals for all user-visible Flows assigned to the bucket, not the bucket-key
value itself.

## Flows By Duration

Duration is computed from authoritative Connection aggregate timestamps:

```text
duration_us = max(0, last_timestamp_us - first_timestamp_us)
```

No `PacketRef` scan or source-capture read is required.

Stable persisted bucket identities:

| ID | Label | Range |
| --- | --- | --- |
| 0 | `0` | `duration_us == 0` |
| 1 | `>0 - <1 ms` | `1 .. 999 us` |
| 2 | `1-10 ms` | `1,000 .. 9,999 us` |
| 3 | `10-100 ms` | `10,000 .. 99,999 us` |
| 4 | `100 ms-1 s` | `100,000 .. 999,999 us` |
| 5 | `1-10 s` | `1,000,000 .. 9,999,999 us` |
| 6 | `10-60 s` | `10,000,000 .. 59,999,999 us` |
| 7 | `1-10 min` | `60,000,000 .. 599,999,999 us` |
| 8 | `10 min+` | `>= 600,000,000 us` |

Stable domain IDs for these buckets are:

- `duration_zero`
- `duration_gt0_lt1ms`
- `duration_1_10ms`
- `duration_10_100ms`
- `duration_100ms_1s`
- `duration_1_10s`
- `duration_10_60s`
- `duration_1_10min`
- `duration_10min_plus`

The ranges have no gaps or overlaps. Single-packet Flows naturally land in
bucket `0`. Multiple packets with identical timestamps also land in bucket
`0`.

This feature does not add duration average, median, or percentile values.

## Flows By Data Size

This is a new histogram and must not be confused with the existing Flows by
Packet Count histogram.

Bucket assignment uses total original bytes of the bidirectional user-visible
Flow. Captured bytes never select the bucket. Each bucket still stores
`flow_count`, `captured_byte_count`, and `original_byte_count`.

Binary KiB/MiB thresholds are used.

Stable persisted bucket identities:

| ID | Label | Range |
| --- | --- | --- |
| 0 | `0-255 B` | `0 .. 255` |
| 1 | `256-1023 B` | `256 .. 1,023` |
| 2 | `1-4 KiB` | `1,024 .. 4,095` |
| 3 | `4-16 KiB` | `4,096 .. 16,383` |
| 4 | `16-64 KiB` | `16,384 .. 65,535` |
| 5 | `64-256 KiB` | `65,536 .. 262,143` |
| 6 | `256 KiB-1 MiB` | `262,144 .. 1,048,575` |
| 7 | `1-10 MiB` | `1,048,576 .. 10,485,759` |
| 8 | `10-100 MiB` | `10,485,760 .. 104,857,599` |
| 9 | `100 MiB+` | `>= 104,857,600` |

Stable domain IDs for these buckets are:

- `original_bytes_0_255`
- `original_bytes_256_1023`
- `original_bytes_1_4kib`
- `original_bytes_4_16kib`
- `original_bytes_16_64kib`
- `original_bytes_64_256kib`
- `original_bytes_256kib_1mib`
- `original_bytes_1_10mib`
- `original_bytes_10_100mib`
- `original_bytes_100mib_plus`

## IP Fragmentation Statistics

Revision 19 adds a capture-wide IP Fragmentation Statistics block:

- Fragmented IP packets.
- IPv4 fragmented packets.
- IPv6 fragmented packets.
- Initial fragments.
- Non-initial fragments.
- IPv6 atomic fragments.
- Flows containing fragments.

Packet-level counters describe capture packets, not only packets attached to
normal user-visible Flows. They must be collected from authoritative unified
import dissection facts without reparsing packet bytes.

### IPv4 Fragmentation

A real IPv4 fragmented packet is:

```text
MF == 1 OR fragment_offset > 0
```

An initial IPv4 fragment is:

```text
fragment_offset == 0 AND MF == 1
```

A non-initial IPv4 fragment is:

```text
fragment_offset > 0
```

### IPv6 Fragmentation

Real IPv6 fragmentation requires a Fragment Header and is not atomic.

An initial IPv6 fragment is:

```text
Fragment Header present AND fragment_offset == 0 AND M == 1
```

A non-initial IPv6 fragment is:

```text
Fragment Header present AND fragment_offset > 0
```

An IPv6 atomic fragment is:

```text
Fragment Header present AND fragment_offset == 0 AND M == 0
```

Atomic fragments are reported separately. They must not contribute to:

- Fragmented IP packets.
- IPv6 fragmented packets.
- Initial fragments.
- Non-initial fragments.

Frozen invariant:

```text
Initial fragments + Non-initial fragments == Fragmented IP packets

Fragmented IP packets =
    IPv4 fragmented packets + IPv6 fragmented packets
```

### Effective IP And Nested Semantics

This feature counts capture packets, not every IP header inside a captured
frame.

For tunnels and nested IP, use the single effective IP classification produced
by the existing unified import traversal / `ImportDissectionFacts`.

Examples:

- `Ethernet -> IPv4 -> GRE -> IPv4(fragment)`
- `Ethernet -> IPv6 -> IP-in-IP -> IPv4(fragment)`
- `GTP-U -> inner IPv4(fragment)`

Do not count outer and inner IP headers as separate fragmentation events for
the same captured frame.

If outer fragmentation stops traversal before an inner packet can be
authoritatively reached, the outer fragmentation is the effective
classification. If traversal reaches an inner IP layer which becomes the
effective import family, use that effective layer.

Outer-vs-inner fragmentation breakdown is out of scope for revision 19.

### Fragmentation Denominators

The v19 Statistics snapshot must retain enough capture-wide packet-family
totals to calculate percentages without rescanning source bytes.

Persist authoritative capture-wide effective packet counters for:

- effectively classified IPv4 packets
- effectively classified IPv6 packets

Percentages use these denominators:

| Metric | Denominator |
| --- | --- |
| Fragmented IP packets | effectively classified IP packets |
| IPv4 fragmented packets | effectively classified IPv4 packets |
| IPv6 fragmented packets | effectively classified IPv6 packets |
| Initial fragments | Fragmented IP packets |
| Non-initial fragments | Fragmented IP packets |
| IPv6 atomic fragments | effectively classified IPv6 packets |
| Flows containing fragments | all user-visible Flows |

Do not derive these denominators from Flow protocol-summary packet totals,
because fragmented and non-flow packets may not become normal Connections.

### Flow-Level Fragmentation Debt

Current code may treat any IPv6 Fragment Header, including atomic fragments,
as `is_ip_fragmented`. Existing Connection fragmented-packet counters may
therefore include atomic fragments.

The v19 implementation must make `Flows containing fragments` mean Flows
containing at least one real IPv4/IPv6 fragment according to this contract.

Do not implement this as a dangerous one-line bool semantic change.
Implementation must carry enough transient fragmentation classification to
distinguish:

- none
- IPv4 initial
- IPv4 non-initial
- IPv6 initial
- IPv6 non-initial
- IPv6 atomic

An equivalent representation is acceptable. Existing downstream uses of
`is_ip_fragmented` must be audited before changing its meaning. Selected-packet
and reassembly behavior must not regress accidentally.

## Capture Import Settings Provenance

Revision 19 adds a dedicated future stable-container section:

```text
capture_import_settings
```

This section is provenance describing how the current materialized
capture/index was built. It is not the current mutable UI Settings state.

Persist exactly these current import-defining settings:

| Stable key | Display name |
| --- | --- |
| `http_use_path_as_service_hint` | `HTTP: use request path as service hint when Host is missing` |
| `ignore_vlan_and_mpls_layers_when_grouping_flows` | `Ignore VLAN and MPLS layers when grouping flows` |
| `ignore_gtpu_teids_when_grouping_inner_flows` | `Ignore GTP-U TEIDs when grouping inner flows` |

Do not persist `use_possible_tls_quic` as import provenance in this feature.
Possible TLS/QUIC is currently projected from persisted metadata and can change
as runtime/presentation policy without rebuilding the materialized Flow model.

### Settings Snapshot Lifecycle

Raw capture:

```text
CaptureImportOptions.settings
    -> immutable/effective capture-import-settings snapshot
```

Save index:

```text
capture-import-settings snapshot
    -> capture_import_settings section
```

Load index:

```text
capture_import_settings section
    -> capture-import-settings snapshot
```

Runtime Settings changes:

```text
may update current AnalysisSettings
MUST NOT mutate the stored import provenance snapshot
```

Statistics report:

```text
reads capture-import-settings snapshot
NOT current mutable AnalysisSettings
```

## Generic Settings Section Wire Contract

The `capture_import_settings` section must use generic entries. Do not encode
the section as three fixed bool fields.

Conceptual section schema v1:

```text
u32 entry_count

for each entry:
    u32 entry_payload_size
    u16 entry_schema_version
    u16 entry_flags
    UTF-8 length-prefixed stable_key
    UTF-8 length-prefixed display_name
    UTF-8 length-prefixed value_text
```

For v1:

```text
entry_schema_version = 1
entry_flags = 0
```

Do not add a `value_type` field in v1. The textual value is the stable generic
fallback representation.

Known current bool settings use canonical wire text:

```text
true
false
```

Known reader behavior:

- known bool key plus `true`/`false` yields semantic bool value
- reports may render known bool values as `Yes` / `No`

Unknown key behavior:

- preserve/read `stable_key`, `display_name`, and `value_text`
- reports may show `display_name | value_text` without understanding semantics

Suggested hard bounds:

- max entries: `64`
- stable key: max `256` UTF-8 bytes
- display name: max `1024` UTF-8 bytes
- value text: max `4096` UTF-8 bytes

Readers must reject structurally malformed lengths and duplicate `stable_key`
values.

For revision 19, the three known import-setting keys are required to be
present exactly once. A missing known key must not be interpreted as `false`.
Unknown additional keys are valid.

## Required Section Policy

For revision 19, `capture_import_settings` is a required section for normal
full index load.

Missing section behavior:

- treat as malformed/incomplete revision-19 index
- reject rather than invent defaults

Index inspection should still be able to enumerate the section inventory.

The current global exact-revision policy still means an old reader will reject
a future index revision before exploiting this forward-extensible payload. The
generic section design is groundwork for future compatibility; this feature
does not change the global compatibility policy.

## Statistics Snapshot v19

Revision 19 will extend the authoritative persisted Statistics snapshot with:

- Flow Duration histogram.
- Flow Original-Byte Size histogram.
- Capture-wide effective IPv4 packet count.
- Capture-wide effective IPv6 packet count.
- IPv4 real-fragment packet count.
- IPv6 real-fragment packet count.
- Initial-fragment packet count.
- Non-initial-fragment packet count.
- IPv6 atomic-fragment packet count.
- Flows-containing-real-fragments count.

The snapshot wire encoding remains explicit stable-container encoding. This
RFC does not specify raw host-ABI structs.

After revision 19 becomes current, revision 18 remains rebuild-required for
full payload load.

## Report Contract

Statistics reports should add new sections without duplicating calculation
logic in individual frontends.

Recommended report order:

1. Report Information.
2. Input.
3. Capture Import Settings.
4. Overview.
5. Capture Time.
6. Protocol Summary.
7. Packet Size Distribution.
8. Flows by Packet Count.
9. Flows by Duration.
10. Flows by Data Size.
11. IP Fragmentation.

Existing renderer organization may place nearby sections slightly differently,
but Capture Import Settings should stay near Input and the new flow histograms
should stay near Flows by Packet Count.

Capture Import Settings report example:

| Setting | Value |
| --- | --- |
| HTTP: use request path as service hint when Host is missing | No |
| Ignore VLAN and MPLS layers when grouping flows | Yes |
| Ignore GTP-U TEIDs when grouping inner flows | No |

Known bool values render as `Yes` / `No`. Unknown future entries render stored
`display_name | value_text` without inventing semantics.

## UI Contract

Qt and Tauri must consume shared C++ Statistics data.

Do not recompute histogram assignment or fragmentation counters in QML or
JavaScript.

Flows by Duration and Flows by Data Size should follow the existing Flows by
Packet Count presentation pattern where practical. The underlying DTO carries
all bucket metrics:

- Flows
- Captured Bytes
- Original Bytes

UI may visualize one metric at a time if that matches current histogram
behavior.

IP Fragmentation is a compact metrics block rather than a bucket histogram.

## Revision Strategy

The design intends one coherent revision transition:

```text
revision 18 -> revision 19
```

This documentation pass must not change the production revision constant.

Do not publish or declare revision 19 stable in an intermediate commit and
then mutate its wire layout later. Implementation passes should develop the
complete v19 wire contract together, then switch the current stable revision
only when the full reader, writer, schema, validation, and tests are coherent.

Every committed intermediate implementation state must remain buildable and
testable according to normal project workflow.

## Implementation Plan

Pass 1:

- Add shared domain/statistics types.
- Add fragmentation classification foundation.
- Do not switch persisted revision.

Pass 2:

- Add capture-wide fragmentation collection.
- Add flow-duration and flow-original-byte histogram builders.

Pass 3:

- Implement complete v19 Statistics snapshot serialization,
  deserialization, validation, and tests.
- Add the generic `capture_import_settings` section.
- Switch revision `18 -> 19` only as one coherent wire-contract pass.

Pass 4:

- Add `CaptureSession` provenance lifecycle.
- Preserve raw/index report parity.

Pass 5:

- Add shared report/DTO projection.

Pass 6:

- Add Qt Statistics presentation.

Pass 7:

- Add Tauri Statistics parity.

Pass 8:

- Update current-state, user documentation, and release-facing wording.

## Consistency Notes

This RFC intentionally differs from current implementation in these areas:

- Current stable revision is `18`, not `19`.
- Current `capture_statistics_snapshot` schema does not contain the new flow
  duration, flow data-size, or capture-wide fragmentation fields.
- Current index layout does not contain `capture_import_settings`.
- Current flow-level fragmentation may treat IPv6 atomic fragments as
  fragmented through the existing `is_ip_fragmented` path.

These are planned implementation gaps, not contradictions in current product
documentation.

# Capture processing settings

`settings.json` is an optional JSON object that CLI commands can load through
`--settings <settings.json>` when the input is a raw capture.

In this documentation, raw capture means a directly opened PCAP or PCAPNG
file. A Pcap Flow Lab index already contains a previously materialized flow
inventory, so `--settings` is rejected for index input instead of re-grouping
that stored inventory.

These settings are applied while the raw flow inventory is built. They are not
display-only preferences.

## Create a settings file

Create a plain text file named, for example, `settings.json`.

Minimal valid example:

```json
{
  "validate_selected_packet_checksums": true
}
```

Current contract:

- the top level must be a JSON object;
- property names are exact;
- values must be JSON booleans: `true` or `false`;
- string values such as `"true"` are invalid;
- `{}` is valid;
- omitted properties keep their default values.

Each command invocation starts from the built-in defaults and then overrides
only the properties present in the file.

## Available settings

| Setting | Type | Default | Affects | Meaning |
| --- | --- | --- | --- | --- |
| `ignore_vlan_and_mpls_layers_when_grouping_flows` | boolean | `false` | Flow grouping | Ignore VLAN and MPLS identity layers when building canonical flow identity. |
| `ignore_gtpu_teids_when_grouping_inner_flows` | boolean | `false` | Flow grouping | Ignore GTP-U TEID identity when grouping otherwise-identical inner flows. |
| `validate_selected_packet_checksums` | boolean | `false` | Selected-packet inspection | Validate supported packet checksums when inspecting a selected packet. |

## Flow grouping settings

### `ignore_vlan_and_mpls_layers_when_grouping_flows`

When this setting is `true`, VLAN and MPLS layers are omitted from the
canonical flow identity path used for grouping.

User-visible effect:

- packets that would otherwise become separate canonical flows can merge;
- canonical flow count can change;
- canonical one-based flow numbers can change;
- grouped flow Protocol Path identity/presentation can change.

What does **not** change:

- the packet still keeps its captured bytes;
- packet decoding still sees VLAN/MPLS data when those bytes are present;
- this changes how flows are grouped, not what bytes exist in the packet.

For a real before/after grouping example, see
[flows](../cli/flows.md).

### `ignore_gtpu_teids_when_grouping_inner_flows`

When this setting is `true`, the GTP-U TEID no longer contributes to canonical
inner-flow identity.

User-visible effect:

- otherwise-identical inner flows carried under different GTP-U TEIDs can be
  grouped together;
- canonical flow count can change;
- canonical one-based flow numbers can change;
- grouped flow Protocol Path identity/presentation can change.

What does **not** change:

- packet bytes are unchanged;
- packet decoding/presentation still keeps GTP-U packet details such as the
  TEID when packet inspection has that information;
- this is a grouping-identity change, not a packet-content rewrite.

## Selected-packet checksum validation

### `validate_selected_packet_checksums`

When this setting is `true`, selected-packet inspection adds checksum
validation information for supported packet types.

Current validated checksums:

- IPv4 header checksum;
- TCP checksum;
- UDP checksum.

Current scope:

- it affects selected-packet inspection only;
- it does **not** change raw capture import;
- it does **not** change flow grouping;
- it does **not** change protocol recognition.

Current presentation behavior distinguishes:

- valid;
- invalid;
- unavailable;
- not checked.

Important current cases:

- source packet bytes must be available for the inspected packet;
- index-backed packet inspection can require an attached readable source
  capture for checksum validation;
- fragmented IP packets are reported as unavailable for TCP/UDP checksum
  validation;
- truncated packets are reported as unavailable when full transport bytes are
  not present;
- some packets can be reported as unavailable with an offload-related note when
  the checksum may not have been finalized in captured bytes;
- IPv4 UDP with checksum value `0` is reported as not checked because the UDP
  checksum is not present in that packet;
- IPv6 UDP with checksum value `0` is reported as invalid because IPv6 requires
  a UDP checksum.

## Complete example

Full current-schema example with verified defaults:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": false,
  "ignore_gtpu_teids_when_grouping_inner_flows": false,
  "validate_selected_packet_checksums": false
}
```

Example relaxed grouping configuration:

```json
{
  "ignore_vlan_and_mpls_layers_when_grouping_flows": true,
  "ignore_gtpu_teids_when_grouping_inner_flows": true,
  "validate_selected_packet_checksums": false
}
```

Conceptually, this relaxed configuration tells raw-capture import to group
flows without VLAN/MPLS identity layers and without GTP-U TEID identity, while
leaving selected-packet checksum validation disabled.

## When settings take effect

For raw capture input:

```text
raw PCAP/PCAPNG
  + settings.json
  -> import / flow construction
  -> canonical flow inventory
```

This is why changing grouping settings can change:

- canonical flow count;
- canonical one-based flow numbers;
- flow-scoped selection results;
- grouped flow Protocol Path identity/presentation.

For index input:

```text
Pcap Flow Lab index
  -> stored flow inventory already exists
```

Because the inventory is already materialized, `--settings` is rejected for
index input rather than re-grouping the saved inventory.

## Settings and canonical flow numbers

Canonical flow numbers are one-based identities within the particular imported
or indexed flow inventory that is currently open.

If grouping settings change that inventory, a number such as `Flow 42` must
not be assumed to identify the same traffic across both imports.

For the detailed worked example, see [flows](../cli/flows.md).

## Commands that accept settings

| Command | Command page | Accepts `--settings` | Input scope |
| --- | --- | --- | --- |
| `summary` | [summary](../cli/summary.md) | Yes | Raw capture only |
| `flows` | [flows](../cli/flows.md) | Yes | Raw capture only |
| `flow-info` | [flow-info](../cli/flow-info.md) | Yes | Raw capture only |
| `packet-info` | [packet-info](../cli/packet-info.md) | Yes | Raw capture only |
| `export-flows` | [export-flows](../cli/export-flows.md) | Yes | Raw capture only |

## Invalid settings files

User-relevant validation behavior:

- malformed JSON is rejected;
- top-level content must be an object;
- unknown property names are rejected, not ignored;
- non-boolean values are rejected;
- trailing commas are rejected as invalid JSON;
- trailing content after the object is rejected;
- comments are not supported and make the file invalid;
- missing or unreadable files are rejected;
- `{}` is accepted;
- omitted properties keep defaults.

For duplicate properties, the practical safe rule is simple: define each
property at most once. The current parser reads properties in order, but
duplicate-key handling is not documented here as a supported public contract.

## Notes

- `settings.json` documents only the public CLI JSON contract accepted by
  `--settings`.
- Some broader frontend/GUI settings exist elsewhere, but they are not valid
  `settings.json` properties unless the CLI parser explicitly accepts them.

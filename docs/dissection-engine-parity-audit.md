# Unified Dissection Import Parity Audit

Date: 2026-07-22
Branch: `feature/unified-packet-dissection`
Verdict: `not-ready-blocking-gaps`

## Scope

This is a static audit of whether the registry-driven shadow dissection engine is
ready to replace legacy `PacketDecoder` specifically for capture import and flow
construction.

The audit is source-grounded only. No build, test, or runtime commands were used
for this pass.

## Files traced

Primary production import path:

- `src/core/services/CaptureImportProcessor.cpp`
- `src/core/services/PacketIngestor.cpp`
- `src/core/decode/PacketDecoder.h`
- `src/core/decode/PacketDecoder.cpp`
- `src/core/domain/IngestedPacket.h`
- `src/core/domain/PacketRef.h`
- `src/core/domain/FlowKey.h`
- `src/core/domain/ProtocolPath.cpp`

Primary shadow path:

- `src/core/dissection/DissectionEngine.cpp`
- `src/core/dissection/CommonDirectDissection.h`
- `src/core/dissection/CommonDirectDissection.cpp`
- `src/core/dissection/DissectionTypes.h`
- `src/core/dissection/modules/ArpModule.cpp`
- `src/core/dissection/modules/ControlMessageModules.cpp`

Parity-contract evidence:

- `tests/unit/CommonDirectDissectionTestSupport.cpp`
- `tests/unit/CommonDirectCollectorTests.cpp`
- `tests/unit/CommonDirectRegistryEngineTests.cpp`
- `tests/unit/CommonDirectLinkDissectionTests.cpp`
- `tests/unit/CommonDirectEncapsulationDissectionTests.cpp`
- `tests/unit/CommonDirectVxlanDissectionTests.cpp`
- `tests/unit/CommonDirectGeneveDissectionTests.cpp`
- `tests/unit/CommonDirectGtpuDissectionTests.cpp`
- `tests/unit/ArpPcapFixtureTests.cpp`
- `tests/data/parsing/pppoe/README.md`
- `tests/data/parsing/vxlan/README.md`
- `tests/data/parsing/geneve/README.md`
- `tests/data/parsing/gtpu/README.md`
- `docs/dissection-engine-rfc.md`
- `CMakeLists.txt`

## Production import contract traced from code

`CaptureImportProcessor` still imports through the legacy path:

1. `decoder_.decode(packet)` produces `DecodedPacket`.
2. Successful `DecodedPacket` carries:
   - `IngestedPacketV4` or `IngestedPacketV6`;
   - `ProtocolPathBuilder`.
3. `CaptureImportProcessor` assigns
   `flow_key.protocol_path_id = intern_protocol_path_id_for_flow_identity(...)`.
4. `PacketIngestor::ingest(...)` persists the packet into connections/flows and
   updates capture summary counts.
5. Hint detection still runs outside decode/import classification.

The persistent import payload is therefore:

- tuple identity from `FlowKeyV4` / `FlowKeyV6`:
  - addresses;
  - ports;
  - `ProtocolId`;
  - later `protocol_path_id`;
- packet metadata from `PacketRef`:
  - packet index;
  - file byte offset;
  - link type;
  - captured/original lengths;
  - timestamps;
  - captured transport payload length;
  - TCP flags;
  - IP-fragment shell flag.

If decode fails, production still has two additional import behaviors:

- selected ARP packets may still be ingested through `ingest_fallback_arp_packet(...)`;
- otherwise an `UnrecognizedPacketRecord` is appended with `PacketRef` plus
  `reason_text`.

`PacketRef` does not store `protocol_path_id`.

## Shadow import facts traced from code

The shadow engine currently stops at `ImportDissectionFacts`.

`DissectionEngine` runs a registered step chain and `ImportDissectionCollector`
reduces steps into:

- `outcome`:
  - `recognized_flow`
  - `recognized_non_flow`
  - `unrecognized`
- `family`
- `terminal_protocol`
- deepest effective flow addresses
- ports
- captured transport payload length
- TCP flags
- IPv4/IPv6 fragmentation shell facts
- ARP addresses
- `physical_path`
- `final_status`
- `stop_reason`
- `step_count`
- `traversed_depth`
- `path_overflowed`

Important differences versus production import payload:

- there is no `PacketRef`;
- there is no byte offset or timestamp payload;
- there is no direct `IngestedPacketV4` / `IngestedPacketV6` object;
- there is no direct `FlowKey` object;
- there is no hint-detection bridge;
- the collector does not touch `ProtocolPathRegistry`.

`ProtocolPathRegistry` growth happens only if some external bridge decides to
intern `shadow.facts().physical_path` for a recognized flow.

## Protocol-family parity matrix

Status vocabulary used here is intentionally narrow:

- `exact`
- `import-equivalent`
- `blocking-gap`
- `coverage-gap`
- `not-applicable`

| Family / slice | Status | Evidence | Audit note |
| --- | --- | --- | --- |
| Ethernet II root | exact | `CommonDirectRegistryEngineTests.cpp`, `CommonDirectLinkDissectionTests.cpp` | Root carrier semantics align for recognized-flow import. |
| VLAN / QinQ / legacy `0x9100` VLAN stacking | exact | `CommonDirectLinkDissectionTests.cpp`, PBB/VXLAN/Geneve/GTP-U fixture families | Path and tuple parity are broadly asserted through wrapped fixture families. |
| IEEE 802.3 / LLC-SNAP | exact | `CommonDirectLinkDissectionTests.cpp`, `LlcSnapPcapFixtureTests.cpp` | Declared child bounds and padding exclusion are already fixture-pinned. |
| Linux cooked SLL / SLL2 | exact | `LinuxCookedPcapFixtureTests.cpp`, registry/link tests | Current supported cooked-root subset is already shadow-covered. |
| ARP | blocking-gap | `PacketDecoder.cpp`, `ArpPcapFixtureTests.cpp`, `CommonDirectRegistryEngineTests.cpp` | Production imports ARP as flow-bearing carrier-path traffic; shadow finalizes as `recognized_non_flow` with `... -> ARP`. |
| IPv4 | exact | `CommonDirectNetworkDissectionTests.cpp`, helper parity assertions | Direct-network tuple/path semantics align. |
| IPv4 options | exact | `CommonDirectNetworkDissectionTests.cpp`, `PacketDetails` coverage | Options remain IPv4-local metadata, not independent path identity. |
| IPv6 | exact | `CommonDirectNetworkDissectionTests.cpp`, fixture parity helpers | Direct-network tuple/path semantics align. |
| IPv6 extension headers | exact | `CommonDirectNetworkDissectionTests.cpp` | Registry-driven extension traversal is shadow-covered and parity-tested. |
| TCP | exact | `CommonDirectTransportDissectionTests.cpp`, helper parity assertions | Ports, flags, and payload-length semantics are asserted. |
| UDP | exact | `CommonDirectTransportDissectionTests.cpp`, overlay family tests | Ordinary UDP and UDP-candidate fallback semantics are strongly covered. |
| SCTP | exact | `CommonDirectTransportDissectionTests.cpp` | Direct SCTP import parity is shadow-covered. |
| ICMP | blocking-gap | `PacketDecoder.cpp`, `CommonDirectRegistryEngineTests.cpp`, `CommonDirectDissectionTestSupport.cpp` | Tuple parity is good, but persistent path differs because shadow contributes `ICMP`. |
| ICMPv6 | blocking-gap | `PacketDecoder.cpp`, `CommonDirectRegistryEngineTests.cpp`, `CommonDirectDissectionTestSupport.cpp` | Same cutover issue as ICMP. |
| IGMP | exact | `CommonDirectRegistryEngineTests.cpp`, encapsulation tests | Both sides keep path at `... -> IPv4` without an IGMP terminal layer. |
| Plain IP encapsulation | exact | `CommonDirectEncapsulationDissectionTests.cpp` | Nested IPv4/IPv6 continuation and fragment shells are already parity-tested. |
| AH | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `AhPcapFixtureTests.cpp` | SPI-bearing path and direct transport continuation are aligned. |
| ESP | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `EspPcapFixtureTests.cpp` | Opaque SPI-bearing terminal behavior is aligned. |
| GRE | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `GrePcapFixtureTests.cpp` | Direct IP, TEB, key identity, and conservative negatives are covered. |
| EoIP | exact | `CommonDirectEoipDissectionTests.cpp`, `EoipPcapFixtureTests.cpp` | GRE-derived tunnel-id identity and bounded inner Ethernet continuation are aligned. |
| MPLS label stack | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `MplsPcapFixtureTests.cpp` | Label-by-label path and BoS continuation semantics are covered. |
| MPLS pseudowire | exact | `CommonDirectMplsPseudowireDissectionTests.cpp`, `MplsPseudowirePcapFixtureTests.cpp` | Control-word and no-control-word paths are parity-tested. |
| PPPoE / PPP | blocking-gap | `CommonDirectLinkDissectionTests.cpp`, `PppoePcapFixtureTests.cpp`, RFC known-gap note | Fixture 20 is an intentional declared-boundary divergence that remains unresolved for cutover. |
| PBB | exact | `CommonDirectLinkDissectionTests.cpp`, `PbbPcapFixtureTests.cpp` | Restricted inner-Ethernet continuation and I-SID identity are fixture-pinned. |
| MACsec | import-equivalent | `CommonDirectLinkDissectionTests.cpp`, `MacsecPcapFixtureTests.cpp` | Shadow emits richer diagnostic facts but still preserves unrecognized import behavior and no persistent path layer. |
| VXLAN | exact | `CommonDirectVxlanDissectionTests.cpp`, `VxlanPcapFixtureTests.cpp`, fixture README | Positive flows, ordinary UDP fallback, identity splits, and fragmentation shells are parity-tested. |
| Geneve | import-equivalent | `CommonDirectGeneveDissectionTests.cpp`, `GenevePcapFixtureTests.cpp`, fixture README | Positive flows are exact; fixture 28 packet 2 keeps only a diagnostic outer partial path with no persistent flow/path. |
| GTP-U | exact | `CommonDirectGtpuDissectionTests.cpp`, `GtpuPcapFixtureTests.cpp`, fixture README | TEID identity, outer UDP fallback, and fragmentation shells are parity-tested. |

## Cutover blockers

| ID | Protocol / family | Fixture or source location | Production behavior | Shadow behavior | Import-visible consequence | Recommended resolution | Risk | Suggested separate commit message |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| B1 | ARP | `src/core/decode/PacketDecoder.cpp`, `tests/unit/ArpPcapFixtureTests.cpp`, `tests/unit/CommonDirectRegistryEngineTests.cpp` | Recognized as flow-bearing import traffic on carrier-only path. | Finalized as `recognized_non_flow` with `LayerKey::arp()`. | Flow counts, summary counts, flow rows, and persistent path identity all change. | Decide whether cutover should preserve legacy ARP-as-flow semantics or intentionally migrate production to non-flow ARP semantics; do not cut over until both import classification and persistent path policy are aligned. | medium | `Align ARP shadow import semantics` |
| B2 | ICMP / ICMPv6 | `src/core/decode/PacketDecoder.cpp`, `tests/unit/CommonDirectRegistryEngineTests.cpp`, `tests/unit/CommonDirectDissectionTestSupport.cpp` | Portless flows are recognized without appending terminal `ICMP` / `ICMPv6` path layers. | Portless flows are recognized with terminal `ICMP` / `ICMPv6` path layers. | Flow grouping by tuple survives, but `ProtocolPathRegistry` identity diverges for every affected flow. | Align shadow path contribution to legacy persistent path semantics, or explicitly migrate production identity and rebaseline all downstream path assumptions in a dedicated commit. | low | `Align ICMP and ICMPv6 path identity` |
| B3 | PPPoE / PPP declared-boundary policy | `tests/data/parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap`, `tests/unit/CommonDirectLinkDissectionTests.cpp`, `docs/dissection-engine-rfc.md` | Legacy accepts PPPoE length `33` with inner IPv4 Total Length `37` and recognizes a flow. | Shadow rejects the inner IPv4 child because it exceeds the enclosing PPPoE declared boundary. | Import outcome flips from recognized flow to malformed/unrecognized. | Make an explicit policy decision in a dedicated commit: either (1) emulate the current legacy permissive bounded behavior locally for PPPoE import, or (2) intentionally tighten production import to declared PPPoE boundaries. Weakening the global `PacketSlice` declared-boundary invariant is not acceptable. | high | `Resolve PPPoE declared-boundary policy` |

## Exact blocking findings

### 1. ARP is not cutover-ready

Production import behavior:

- `PacketDecoder::decode(...)` recognizes IPv4 ARP directly and returns
  `IngestedPacketV4` with `ProtocolId::arp`.
- The resulting path is only the outer carrier path already present in
  `base_builder`.
- Production fixture tests expect real flow rows and packet counts for ARP.

Shadow behavior:

- `dissect_arp(...)` emits `LayerKey::arp()`.
- `dissect_arp(...)` sets `TerminalDisposition::recognized_non_flow`.
- `ImportDissectionCollector` finalizes ARP as `recognized_non_flow`.
- `CommonDirectRegistryEngineTests.cpp` explicitly expects
  `format_shadow_path(arp_shadow) == "EthernetII -> ARP"`.

Impact:

- summary packet/flow counts would change;
- ARP would move from flow rows to a non-flow bucket;
- persistent path identity would change from carrier-only to `... -> ARP`;
- carrier-wrapped ARP cases also remain classification-divergent where shadow
  still finalizes as `recognized_non_flow`, even when some wrapped-path text is
  already kept compatible with legacy.

This is a cutover blocker.

### 2. ICMP and ICMPv6 are not cutover-ready for persistent path identity

Production import behavior:

- direct and nested plain-IP ICMP / ICMPv6 flows are recognized as portless
  flows;
- `PacketDecoder` does not append `LayerKey::icmp()` or `LayerKey::icmpv6()` to
  the persistent path.

Shadow behavior:

- `dissect_icmp(...)` and `dissect_icmpv6(...)` emit path contributions;
- collector tests and registry tests explicitly expect shadow path text such as:
  - `EthernetII -> IPv4 -> ICMP`
  - `EthernetII -> IPv6 -> ICMPv6`
- helper `expect_shadow_matches_legacy_portless_flow(...)` exists precisely
  because path parity is not exact even when tuple parity is exact.

Impact:

- flow grouping by tuple still matches;
- `ProtocolPathRegistry` identity would differ for every ICMP/ICMPv6 flow;
- any cutover would split current flow/path semantics for direct and tunneled
  ICMP / ICMPv6 traffic.

This is a cutover blocker.

### 3. PPPoE fixture 20 remains an intentional semantic divergence

Fixture:

- `tests/data/parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap`

Current asserted behavior:

- PPPoE declared payload length is `33`;
- inner IPv4 Total Length is `37`;
- legacy bounded decoding still recognizes the packet as
  `PPPoE -> PPP -> IPv4 -> UDP`;
- shadow rejects the inner IPv4 child because it would exceed the enclosing
  declared PPPoE boundary.

Impact:

- legacy import yields a recognized flow;
- shadow yields `unrecognized` with `StopReason::malformed`;
- this is not a presentation difference.

This is a cutover blocker until the declared-boundary policy is explicitly
chosen and production behavior is aligned to it.

## Cutover integration prerequisites

These are not parser-semantic blockers by themselves. They are still required
before any production import cutover can be called ready.

| ID | Area | Current state | Required before cutover |
| --- | --- | --- | --- |
| I1 | Import adapter | Shadow ends at `ImportDissectionFacts`. Production import persists `DecodedPacket`, `IngestedPacketV4` / `IngestedPacketV6`, `FlowKey`, `PacketRef`, protocol-path interning, `UnrecognizedPacketRecord`, and existing hint-detection side effects. | Add an adapter that maps shadow facts into the existing import payload contract without changing runtime semantics. |
| I2 | Full-session parity harness | Current shadow tests are mostly packet- and fixture-local. | Add a whole-session legacy-vs-shadow harness that compares summary counters, flow rows, connections, packet counts per flow, unrecognized rows, protocol-path registry contents, and persisted packet metadata. |
| I3 | Real-capture correctness and performance validation | The current audit is static and fixture-driven only. | Validate representative real captures for correctness, import throughput, memory, and no-regression behavior before a single production cutover commit. |

## Diagnostic-only difference confirmed as safe for persistence

The cleanest audited example is packet 2 of:

- `tests/data/parsing/geneve/28_geneve_udp_declared_bounds_matrix.pcap`

Exact shadow traversal:

1. `EthernetII`
2. `IPv4`
3. attempted `UDP` step
4. UDP declared-length validation fails before Geneve child construction

Observed shadow result:

- `outcome == unrecognized`
- `stop_reason == malformed`
- `terminal_protocol == udp`
- no ports
- no Geneve facts
- no inner flow facts
- `format_shadow_path(...) == "EthernetII -> IPv4"`

Collector/persistence consequence:

- there is no flow candidate;
- `ImportDissectionCollector` itself does not touch the registry;
- `CommonDirectGeneveDissectionTests.cpp` manually proves registry size remains
  `0` because no recognized flow is interned;
- no persistent `protocol_path_id` would be assigned;
- production import remains unrecognized.

This is acceptable as a diagnostic-only difference, not a persistent identity
difference.

## Fragmentation summary matrix

| Slice | Status | Audit note |
| --- | --- | --- |
| Direct IPv4 fragmentation shells | exact | Covered in direct network tests and preserved as import shell behavior. |
| Direct IPv6 fragmentation shells | exact | Covered through IPv6 extension tests and fragment-shell semantics. |
| Plain-IP inner IPv4 / IPv6 fragmentation | exact | Encapsulation tests cover nested fragment-shell continuation and conservative stops. |
| VXLAN outer IPv4 / IPv6 fragmentation | exact | Fixture contract and shadow tests pin the current outer-fragment shell behavior. |
| Geneve outer IPv4 / IPv6 fragmentation | exact | Fixture contract and shadow tests pin the current outer-fragment shell behavior. |
| GTP-U outer IPv4 / IPv6 fragmentation | exact | Fixture contract and shadow tests pin the current outer-fragment shell behavior. |
| GRE / EoIP outer fragmentation gating | exact | Encapsulation and EoIP shadow suites cover the current no-recursive continuation rules. |

## UDP candidate fallback matrix

| Candidate family | Invalid candidate after valid UDP | Unsupported inner payload | Malformed UDP before candidate dispatch | Capture truncation | Nested inner UDP terminal behavior |
| --- | --- | --- | --- | --- | --- |
| VXLAN | ordinary outer UDP fallback | ordinary outer UDP fallback | no-flow / malformed before VXLAN recognition | conservative truncated or no-flow stop | inner UDP stays terminal UDP, no recursive overlay decode |
| Geneve | ordinary outer UDP fallback after a successfully parsed UDP layer, according to the fixture contract | ordinary outer UDP fallback | no manufactured UDP fallback; fixture 28 packet 2 remains unrecognized, shadow retains only the diagnostic `EthernetII -> IPv4` traversal path, and no flow or persistent registry entry is created | conservative truncated or no-flow stop | inner UDP stays terminal UDP, no recursive overlay decode |
| GTP-U | ordinary outer UDP fallback for unsupported or control-message cases | ordinary outer UDP fallback | no-flow / malformed before GTP-U recognition | conservative truncated or no-flow stop | inner UDP stays terminal UDP, no recursive overlay decode |

## Flow-construction and registry findings

- `FlowKeyV4` / `FlowKeyV6` still persist identity as
  `addresses + ports + protocol + protocol_path_id`.
- `ProtocolPathRegistry::intern(...)` still returns `kInvalidProtocolPathId` for
  empty paths and only grows for explicit non-empty interning.
- `PacketRef` still carries no `protocol_path_id`.
- Shadow collector currently has no built-in bridge that:
  - builds `FlowKey`;
  - copies timestamps/byte offsets into `PacketRef`;
  - runs the existing hint-detection policy;
  - writes `UnrecognizedPacketRecord`.

So even exact semantic parity at the step level is not yet enough for a direct
runtime cutover.

## Coverage limitations

The shadow test surface is broad, but this audit still does not prove full
production-import equivalence end to end.

- There is no full-session legacy-vs-shadow import harness yet.
- There is no exercised adapter from `ImportDissectionFacts` into persisted
  `PacketRef` / `FlowKey` / `UnrecognizedPacketRecord` structures.
- The static audit does not prove byte-for-byte equivalence for:
  - timestamps;
  - file byte offsets;
  - hint-detection side effects;
  - final `CaptureState` persistence ordering.
- Families already marked `exact` above are exact only to the extent currently
  asserted by fixture and shadow tests; they are not yet backed by a universal
  capture-session diff harness.

## Compile-pressure inventory

The current test decomposition reduces compile pressure, but the heavy
translation units are still concentrated in a handful of shadow comparison
sources.

This is a byte-size inventory only. Per-file line counts and largest-function
measurements were not repeated in this static parity pass; if further test
decomposition becomes necessary, those remain a separate compile-pressure audit
task.

| Translation unit | Size (bytes) |
| --- | ---: |
| `tests/unit/CommonDirectCoreDissectionTests.cpp` | 370 |
| `tests/unit/CommonDirectDissectionTests.cpp` | 847 |
| `tests/unit/CommonDirectEncapsulationDissectionTests.cpp` | 99890 |
| `tests/unit/CommonDirectEoipDissectionTests.cpp` | 24815 |
| `tests/unit/CommonDirectGeneveDissectionTests.cpp` | 34345 |
| `tests/unit/CommonDirectGtpuDissectionTests.cpp` | 23076 |
| `tests/unit/CommonDirectLinkDissectionTests.cpp` | 87882 |
| `tests/unit/CommonDirectMplsPseudowireDissectionTests.cpp` | 28615 |
| `tests/unit/CommonDirectNetworkDissectionTests.cpp` | 67786 |
| `tests/unit/CommonDirectTransportDissectionTests.cpp` | 25158 |
| `tests/unit/CommonDirectVxlanDissectionTests.cpp` | 37533 |

The test-only `-O0` / `/Od` mitigation is still purely a build-memory measure.
It does not reduce the semantic audit work required for cutover.

## Architecture-isolation finding

Production import is still fully isolated from shadow code:

- `CaptureImportProcessor` still calls `PacketDecoder`;
- no runtime flag switches import to `DissectionEngine`;
- no production decoder path was deleted or bypassed in the traced code.

That isolation is good for safety, but it also means the branch has not yet
proved a production import cutover path.

## Final verdict

The shadow engine is not ready to replace `PacketDecoder` for capture import and
flow construction.

Recommended verdict:

- `not-ready-blocking-gaps`

Reason:

1. ARP import semantics differ materially.
2. ICMP / ICMPv6 persistent protocol-path identity differs materially.
3. PPPoE fixture 20 remains an intentional import-semantic divergence.

Everything else inspected here points to a strong migration foundation:

- supported transport and overlay coverage is broad;
- many positive/fallback paths already assert exact parity;
- some negative paths are only diagnostic differences and do not leak into
  persistent flow identity.

But the remaining blockers are import-contract blockers, not cosmetic ones.

## Minimum expected sequence before cutover

1. Align ICMP and ICMPv6 protocol paths with the chosen persistent identity policy.
2. Align ARP import classification and persistent path semantics.
3. Resolve PPPoE fixture 20 declared-boundary behavior explicitly.
4. Add the import adapter and full-session parity harness.
5. Validate representative real captures and import performance.
6. Cut over production import in a single dedicated change.

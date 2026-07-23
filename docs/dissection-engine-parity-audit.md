# Unified Dissection Import Parity Audit

Date: 2026-07-22
Branch: `feature/unified-packet-dissection`
Verdict: `not-ready-coverage-gaps`

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
- `src/core/services/DissectionImportAdapter.h`
- `src/core/services/DissectionImportAdapter.cpp`
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
- `tests/unit/DissectionImportAdapterTests.cpp`
- `tests/unit/CommonDirectCollectorTests.cpp`
- `tests/unit/DissectionImportSessionParityTests.cpp`
- `tests/unit/ImportValidationTests.cpp`
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
- `docs/dissection-import-validation.md`
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

The shadow engine itself currently stops at `ImportDissectionFacts`.

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

There is now a narrow bridge at:

- `src/core/services/DissectionImportAdapter.h`
- `src/core/services/DissectionImportAdapter.cpp`

That adapter converts finalized `ImportDissectionFacts` into the existing
`DecodedPacket` shape for recognized flows only. It does not:

- run packet parsing;
- touch `CaptureState`;
- build `PacketRef` capture-context metadata;
- intern paths;
- assign `protocol_path_id`;
- run hint detection;
- switch production import away from `PacketDecoder`.

## Protocol-family parity matrix

Status vocabulary used here is intentionally narrow:

- `exact`
- `import-equivalent`
- `coverage-gap`
- `not-applicable`

| Family / slice | Status | Evidence | Audit note |
| --- | --- | --- | --- |
| Ethernet II root | exact | `CommonDirectRegistryEngineTests.cpp`, `CommonDirectLinkDissectionTests.cpp` | Root carrier semantics align for recognized-flow import. |
| VLAN / QinQ / legacy `0x9100` VLAN stacking | exact | `CommonDirectLinkDissectionTests.cpp`, PBB/VXLAN/Geneve/GTP-U fixture families | Path and tuple parity are broadly asserted through wrapped fixture families. |
| IEEE 802.3 / LLC-SNAP | exact | `CommonDirectLinkDissectionTests.cpp`, `LlcSnapPcapFixtureTests.cpp` | Declared child bounds and padding exclusion are already fixture-pinned. |
| Linux cooked SLL / SLL2 | exact | `LinuxCookedPcapFixtureTests.cpp`, registry/link tests | Current supported cooked-root subset is already shadow-covered. |
| ARP | exact | `PacketDecoder.cpp`, `ArpPcapFixtureTests.cpp`, `CommonDirectRegistryEngineTests.cpp` | Visible ARP step remains, but supported ARP now imports as a portless IPv4 flow on the same carrier-only persistent path as production. |
| IPv4 | exact | `CommonDirectNetworkDissectionTests.cpp`, helper parity assertions | Direct-network tuple/path semantics align. |
| IPv4 options | exact | `CommonDirectNetworkDissectionTests.cpp`, `PacketDetails` coverage | Options remain IPv4-local metadata, not independent path identity. |
| IPv6 | exact | `CommonDirectNetworkDissectionTests.cpp`, fixture parity helpers | Direct-network tuple/path semantics align. |
| IPv6 extension headers | exact | `CommonDirectNetworkDissectionTests.cpp` | Registry-driven extension traversal is shadow-covered and parity-tested. |
| TCP | exact | `CommonDirectTransportDissectionTests.cpp`, helper parity assertions | Ports, flags, and payload-length semantics are asserted. |
| UDP | exact | `CommonDirectTransportDissectionTests.cpp`, overlay family tests | Ordinary UDP and UDP-candidate fallback semantics are strongly covered. |
| SCTP | exact | `CommonDirectTransportDissectionTests.cpp` | Direct SCTP import parity is shadow-covered. |
| ICMP | exact | `PacketDecoder.cpp`, `CommonDirectRegistryEngineTests.cpp`, `CommonDirectDissectionTestSupport.cpp` | Visible ICMP step remains, but persistent path now matches legacy carrier/network layers exactly. |
| ICMPv6 | exact | `PacketDecoder.cpp`, `CommonDirectRegistryEngineTests.cpp`, `CommonDirectDissectionTestSupport.cpp` | Visible ICMPv6 step remains, but persistent path now matches legacy carrier/network layers exactly. |
| IGMP | exact | `CommonDirectRegistryEngineTests.cpp`, encapsulation tests | Both sides keep path at `... -> IPv4` without an IGMP terminal layer. |
| Plain IP encapsulation | exact | `CommonDirectEncapsulationDissectionTests.cpp` | Nested IPv4/IPv6 continuation and fragment shells are already parity-tested. |
| AH | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `AhPcapFixtureTests.cpp` | SPI-bearing path and direct transport continuation are aligned. |
| ESP | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `EspPcapFixtureTests.cpp` | Opaque SPI-bearing terminal behavior is aligned. |
| GRE | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `GrePcapFixtureTests.cpp` | Direct IP, TEB, key identity, and conservative negatives are covered. |
| EoIP | exact | `CommonDirectEoipDissectionTests.cpp`, `EoipPcapFixtureTests.cpp` | GRE-derived tunnel-id identity and bounded inner Ethernet continuation are aligned. |
| MPLS label stack | exact | `CommonDirectEncapsulationDissectionTests.cpp`, `MplsPcapFixtureTests.cpp` | Label-by-label path and BoS continuation semantics are covered. |
| MPLS pseudowire | exact | `CommonDirectMplsPseudowireDissectionTests.cpp`, `MplsPseudowirePcapFixtureTests.cpp` | Control-word and no-control-word paths are parity-tested. |
| PPPoE / PPP | exact | `CommonDirectLinkDissectionTests.cpp`, `PppoePcapFixtureTests.cpp`, RFC bounded-child note | Fixture 20 now confirms that legacy import and shadow traversal both reject inner packets whose declared IP length exceeds the bounded PPPoE payload. |
| PBB | exact | `CommonDirectLinkDissectionTests.cpp`, `PbbPcapFixtureTests.cpp` | Restricted inner-Ethernet continuation and I-SID identity are fixture-pinned. |
| MACsec | import-equivalent | `CommonDirectLinkDissectionTests.cpp`, `MacsecPcapFixtureTests.cpp` | Shadow emits richer diagnostic facts but still preserves unrecognized import behavior and no persistent path layer. |
| VXLAN | exact | `CommonDirectVxlanDissectionTests.cpp`, `VxlanPcapFixtureTests.cpp`, fixture README | Positive flows, ordinary UDP fallback, identity splits, and fragmentation shells are parity-tested. |
| Geneve | import-equivalent | `CommonDirectGeneveDissectionTests.cpp`, `GenevePcapFixtureTests.cpp`, fixture README | Positive flows are exact; fixture 28 packet 2 keeps only a diagnostic outer partial path with no persistent flow/path. |
| GTP-U | exact | `CommonDirectGtpuDissectionTests.cpp`, `GtpuPcapFixtureTests.cpp`, fixture README | TEID identity, outer UDP fallback, and fragmentation shells are parity-tested. |

## Cutover blockers

No known protocol-family semantic blockers remain in the audited fixture set.

Resolved notes:

- ARP is no longer an active blocker. Shadow still emits a visible
  `DissectionLayerKind::arp` step with `ArpFacts`, but supported ARP now
  finalizes as a recognized portless IPv4 flow and no longer contributes a
  persistent `LayerKey::arp()` path layer.
- ICMP and ICMPv6 are no longer active blockers. Shadow still emits visible
  `DissectionLayerKind::icmp` / `DissectionLayerKind::icmpv6` steps with typed
  facts, but successful terminal steps no longer contribute persistent
  `LayerKey::icmp()` / `LayerKey::icmpv6()` path material.
- PPPoE / PPP is no longer an active blocker. Fixture
  `20_pppoe_bad_length_extra_payload.pcap` now follows the same strict
  declared-boundary policy in both legacy import and shadow traversal, so an
  inner IPv4 packet whose declared length exceeds the bounded PPPoE payload is
  rejected as malformed / unrecognized rather than recovered as a UDP flow.

## Exact blocking findings

### 1. ARP import/path parity is resolved

Current behavior:

- `PacketDecoder::decode(...)` and shadow import both recognize supported IPv4
  ARP as a portless IPv4 flow with `ProtocolId::arp`;
- shadow still emits a visible `arp` step and keeps `ArpFacts` available for
  diagnostics and packet-details presentation;
- sender/target protocol addresses now populate the shadow flow endpoints;
- the persistent path now remains on the production-compatible enclosing
  carrier/tunnel path only, without a terminal `LayerKey::arp()`.

Effect:

- summary packet counts and flow-row accounting now match legacy production for
  supported ARP contexts;
- `ProtocolPathRegistry` identity no longer diverges solely because the terminal
  protocol is ARP;
- malformed or truncated ARP remains conservative and does not fabricate flows
  or registry entries.

### 2. ICMP and ICMPv6 path parity is resolved

Current behavior:

- direct and nested plain-IP ICMP / ICMPv6 flows remain recognized as portless
  flows;
- visible `icmp` / `icmpv6` dissection steps and typed facts remain present;
- successful terminal ICMP / ICMPv6 steps no longer contribute persistent
  `LayerKey::icmp()` / `LayerKey::icmpv6()` path material.

Effect:

- shadow persistent paths now match legacy production paths exactly for direct
  and already covered encapsulated ICMP / ICMPv6 flows;
- `ProtocolPathRegistry` identity no longer diverges solely because the terminal
  protocol is ICMP or ICMPv6.

### 3. PPPoE fixture 20 now confirms strict bounded-child parity

Fixture:

- `tests/data/parsing/pppoe/20_pppoe_bad_length_extra_payload.pcap`

Current asserted behavior:

- PPPoE declared payload length is `33`;
- inner IPv4 Total Length is `37`;
- legacy import rejects the bounded inner IPv4 packet instead of recovering a
  UDP flow from bytes beyond the declared PPPoE payload;
- shadow rejects the same inner IPv4 child because it exceeds the enclosing
  declared PPPoE boundary.

Impact:

- legacy import yields no flow;
- shadow yields `unrecognized` with `StopReason::malformed`;
- there is no persistent protocol-path entry or flow-registry growth on either
  side.

This fixture is no longer a semantic blocker; it now pins the strict
declared-boundary policy that production cutover must preserve.

## Cutover integration prerequisites

These are not parser-semantic blockers by themselves. They are still required
before any production import cutover can be called ready.

| ID | Area | Current state | Required before cutover |
| --- | --- | --- | --- |
| I1 | Import adapter | Adapter-core now exists and is unit-covered at the `ImportDissectionFacts -> DecodedPacket` boundary. Runtime import still persists `PacketRef` capture context, protocol-path interning, `UnrecognizedPacketRecord`, and existing hint-detection side effects through the legacy `PacketDecoder` path. | Wire the adapter through `CaptureImportProcessor` only after the whole-session parity harness proves no regression in persisted packet/session state. |
| I2 | Full-session parity harness | Implemented for a committed fixture-session corpus through `tests/unit/DissectionImportSessionParityTests.cpp`. The harness imports the same complete capture through legacy runtime import and a test-only unified path, then compares summary accounting, connection/flow grouping, `FlowKey`, `PacketRef`, protocol-path registry contents, unrecognized records, and persisted hint side effects. | Extend the parity corpus further only where remaining cutover risk is still unexercised. |
| I3 | Real-capture correctness and performance validation | Developer-only validation tooling now exists for legacy/unified compare, packet-level diagnose attribution, single-mode throughput, peak-memory measurement, classic-PCAP staged-prefix parity, and PCAPNG validation coverage. Real-capture runs are still pending. | Run representative real captures and review correctness, import throughput, memory, and no-regression behavior before a single production cutover commit. |

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

- There is now a committed full-session legacy-vs-shadow parity harness for a
  representative fixture corpus, including multi-packet grouping, overlays,
  fragmentation, hints, and negative cases such as PPPoE fixture 20 and
  Geneve fixture 28.
- That harness does not yet claim exhaustive coverage for every committed
  fixture family or every reader/import mode permutation.
- The committed session/tool coverage now includes a dedicated classic-PCAP
  staged-prefix large-packet parity case, including a packet whose transport
  header falls beyond the initial staged prefix and whose `origlen` exceeds
  `caplen`.
- The current parity corpus is still fixture-driven; it does not replace
  representative real-capture correctness, throughput, memory, or teardown
  validation.
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

- `not-ready-coverage-gaps`

Reason:

1. No known protocol-family semantic blockers remain, but import-adapter,
   whole-session parity, and real-capture validation work are still incomplete.

Everything else inspected here points to a strong migration foundation:

- supported transport and overlay coverage is broad;
- many positive/fallback paths already assert exact parity;
- some negative paths are only diagnostic differences and do not leak into
  persistent flow identity.

The remaining gaps are cutover-readiness and coverage gaps, not parser-semantic
blockers.

## Minimum expected sequence before cutover

1. Run the developer-only validation tool on representative real captures.
2. Review correctness, throughput, and peak-memory deltas.
3. Cut over production import in a single dedicated change.

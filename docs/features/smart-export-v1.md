# Smart Export v1

Status: proposed and implemented as the first Smart export pass.

## Smart export v1 semantics

### Flows to export

Exactly one scope is chosen:

- Current flow
- Selected flows
- Unselected flows
- All flows

### Base packet selection

Exactly one base rule is chosen:

- All packets
- First N packets
- First M original bytes

#### Base rule semantics

- All packets: export all packets from the chosen flows.
- First N packets: export the first N packets of each chosen flow.
- First M original bytes:
  - accumulate original packet lengths in flow order
  - include packets until the threshold is reached
  - include the packet that crosses the threshold

### Additional packet retention

Optional rules:

- Include last packet
- Include every K-th packet after the base prefix

#### Additional rule semantics

- Include last packet: include the last packet of the flow even if it was not already in the base prefix.
- Include every K-th packet after the base prefix:
  - applies only after the base prefix ends
  - adds sparse packets later in the flow
- If base mode is All packets, these additional options are disabled in the UI.

### Final packet-selection semantics

For each chosen flow, a packet is exported if it matches:

- the base rule
- OR Include last packet
- OR Include every K-th packet after the base prefix

A packet must never be exported more than once.

### Efficiency / scale assumptions

Smart export v1 assumes captures are usually under 100 million packets.

Implementation should prefer:

- a 1-byte-per-packet selection array / marker array
- one marking phase over flow packet refs
- one final linear export pass in original capture order

Do not:

- build a packet list with duplicates and sort/deduplicate later
- export in per-flow order
- use expensive post-hoc duplicate cleanup

### Output order

Exported packets must preserve original capture order.

### Byte semantics

- First M original bytes uses original packet length
- not captured length

### Out of scope for v1

- protocol-specific rules
- time-based activity or liveness rules
- output-size preview
- advanced presets

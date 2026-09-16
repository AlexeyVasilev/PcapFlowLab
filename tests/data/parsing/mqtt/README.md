# MQTT Parsing Fixtures

This directory contains the planned permanent PCAP fixture set for the target
first PcapFlowLab MQTT recognition behavior.

MQTT detection is not implemented in PcapFlowLab at the time this fixture set
is introduced. These PCAPs define the target first detection-only contract for
the future MQTT feature; they do not document current recognized behavior.

## Target First MQTT Support

The intended first MQTT support is detection-only. It should live in the
application protocol hint path and recognize MQTT only from a structurally
valid MQTT CONNECT frame that is wholly available in one examined TCP payload.

Target behavior:

- TCP only.
- CONNECT-only confirmation.
- MQTT 3.1, MQTT 3.1.1, and MQTT 5.0.
- Content-based recognition with no mandatory port requirement.
- TCP/1883 alone does not imply MQTT.
- TCP/8883 alone does not imply MQTT.
- TLS traffic on TCP/8883 must remain TLS when the payload is TLS.
- No MQTT-over-TLS inference merely from the port.
- No MQTT over WebSockets.
- No MQTT-SN.
- No Client Identifier, Username, Password, or Will Topic extraction into
  `service_hint`.
- No MQTT-specific Packet Summary, Stream rows, or Stream Item Data.
- No special TCP reassembly.
- A CONNECT split across TCP segments may remain undetected initially.
- Bytes after the first complete CONNECT frame may belong to another coalesced
  MQTT frame and must not prevent detection.

After implementation, successful MQTT detection should produce Detected
Protocol `MQTT` / protocol hint `mqtt`, while service hint remains empty.

Before MQTT implementation, PcapFlowLab is expected to leave these positive
fixtures as ordinary TCP flows.

## Local Generation

The local helper script is intentionally not committed and should remain a
local generation helper only:

```bash
python tmp/generate_mqtt_pcaps.py --output-dir tests/data/parsing/mqtt --force
```

Run the command from the repository root after installing Scapy locally. The
script creates the output directory, overwrites exactly the ten fixture files
listed below when `--force` is supplied, emits classic Ethernet `.pcap` files,
and prints only the generated paths.

To write into the current directory on a separate fixture-generation VM, `cd`
to the desired output directory and run the script without `--output-dir`:

```bash
python /path/to/tmp/generate_mqtt_pcaps.py --force
```

Do not edit generated packet bytes by hand. If a fixture needs to change,
adjust the local generator and regenerate the PCAPs.

## Shared Deterministic Values

- Client MAC: `02:00:00:00:47:01`
- Server MAC: `02:00:00:00:47:02`
- Client IPv4: `192.0.2.130`
- Server IPv4: `192.0.2.140`
- Client ephemeral TCP port: `57000`
- Normal MQTT server port: `1883`
- Non-standard MQTT test port: `31883`
- Client initial TCP sequence: `1000`
- Server initial TCP sequence: `5000`

All fixtures use deterministic Ethernet / IPv4 / TCP / Raw packets with `PA`
flags, stable ACK values, stable timestamps, and Scapy-generated IPv4/TCP
checksums. Full TCP handshakes are not required for these future
application-protocol recognition fixtures.

## Target CONNECT Validation Contract

The future recognizer is expected to validate:

- MQTT fixed header packet type `CONNECT` with fixed-header flags `0`.
- MQTT Remaining Length as a complete one- to four-byte Variable Byte Integer.
- The first complete CONNECT frame fits in the current TCP payload.
- Exact protocol name / protocol level combinations:
  - MQTT 3.1: `MQIsdp` + level `3`
  - MQTT 3.1.1: `MQTT` + level `4`
  - MQTT 5.0: `MQTT` + level `5`
- CONNECT Flags reserved bit `0` is clear.
- Will QoS is not `3`.
- If Will Flag is clear, Will QoS and Will Retain are clear.
- Keep Alive is present.
- MQTT 5 CONNECT Property Length is syntactically valid and bounded.
- Length-delimited CONNECT payload fields are structurally walkable within the
  declared CONNECT frame.

For a valid CONNECT, the walked CONNECT fields should end exactly at the
declared CONNECT frame end. Bytes after that frame end may be a later
coalesced MQTT frame.

## Fixture Map

### `01_mqtt311_connect_port1883.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: MQTT 3.1.1
- CONNECT fields: Protocol Name `MQTT`, Protocol Level `4`, Clean Session
  only, Keep Alive `60`, Client Identifier `pfl311-client`
- Purpose: basic positive MQTT 3.1.1 detection and normal TCP/1883 baseline
- Future expected PFL behavior: one TCP Flow, Detected Protocol `MQTT`,
  protocol hint `mqtt`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: should normally decode as MQTT

### `02_mqtt5_rich_connect_nonstandard_port.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:31883`
- MQTT version: MQTT 5.0
- CONNECT Flags: Username, Password, Will Retain, Will QoS 1, Will Flag, and
  Clean Start set; reserved bit clear (`0xEE`)
- CONNECT Properties: Session Expiry Interval `60`
- Client Identifier: `pfl5-` plus 96 ASCII `A` characters
- Will Properties: Will Delay Interval `5`
- Will Topic: `pfl/status`
- Will Payload: `offline`
- Username: `pfl-user`
- Password: `pfl-pass`
- Purpose: positive MQTT 5 detection, non-port-gated recognition, MQTT 5
  property skipping, Will field walking, Username/Password bounds walking, and
  multi-byte Remaining Length
- Future expected PFL behavior: one TCP Flow, Detected Protocol `MQTT`,
  protocol hint `mqtt`, empty service hint
- Future PFL must not expose Client Identifier, Username, Password, or Will
  Topic as service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: because this uses a non-standard TCP port, Wireshark may
  leave it as TCP unless heuristic detection or Decode As is used
- Boundary: this fixture proves detection is content-based rather than gated
  to TCP/1883

### `03_mqtt31_connect_port1883.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: MQTT 3.1
- CONNECT fields: Protocol Name `MQIsdp`, Protocol Level `3`, Clean Session
  only, Keep Alive `60`, Client Identifier `pfl31-client`
- Purpose: positive MQTT 3.1 support and old protocol-name/version pair
- Future expected PFL behavior: one TCP Flow, Detected Protocol `MQTT`,
  protocol hint `mqtt`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: should normally decode as MQTT if the dissector supports the
  old 3.1 handshake

### `04_mqtt311_connect_plus_pingreq_same_payload.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: MQTT 3.1.1
- Payload: a valid CONNECT frame followed immediately by a valid PINGREQ
  frame `C0 00` inside the same TCP Raw payload
- Purpose: positive coalescing case proving the detector validates the first
  complete CONNECT frame and does not require TCP payload size to equal CONNECT
  frame size
- Future expected PFL behavior: one TCP Flow, Detected Protocol `MQTT`,
  protocol hint `mqtt`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: should normally show both MQTT frames in the TCP payload

### `05_mqtt_garbage_port1883.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- Payload: `PFL-NOT-MQTT\r\n`
- Malformed intent: not an MQTT CONNECT frame
- Purpose: negative case proving TCP/1883 alone is insufficient
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: may select MQTT because of TCP/1883 and display malformed
  data; this does not define PFL behavior

### `06_mqtt_invalid_fixed_header_flags.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: otherwise valid MQTT 3.1.1 CONNECT
- Malformed intent: fixed-header first byte changed from `0x10` to `0x11`
- Purpose: negative case proving CONNECT fixed-header flags must be validated
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: may identify MQTT but mark it malformed

### `07_mqtt_protocol_name_level_mismatch.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- Malformed intent: Protocol Name `MQTT` with Protocol Level `3`
- Purpose: negative case proving the detector requires known valid
  name/version pairs; `MQTT` plus arbitrary level is not enough
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: may show MQTT with unsupported or malformed version details

### `08_mqtt_invalid_connect_flags_reserved_bit.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: otherwise valid MQTT 3.1.1 CONNECT
- Malformed intent: CONNECT Flags `0x03`, setting Clean Session and the
  reserved bit
- Purpose: negative case proving internal CONNECT Flags must be validated, not
  just fixed header and protocol name
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP

### `09_mqtt_declared_remaining_length_too_large.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: based on a small valid MQTT 3.1.1 CONNECT
- Malformed intent: declared Remaining Length exceeds the actual TCP payload
  bytes present
- Purpose: negative case proving the recognizer must reject an incomplete
  CONNECT frame and not accept a valid-looking prefix
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: may present this as truncated or malformed MQTT

### `10_mqtt_client_id_length_exceeds_frame.pcap`

- Packets: `1`
- Direction: client to server
- IPv4/TCP: `192.0.2.130:57000` -> `192.0.2.140:1883`
- MQTT version: MQTT 3.1.1 frame with valid outer Remaining Length for the
  bytes actually present
- Malformed intent: Client Identifier length field declares `20` bytes, but
  only `3` bytes (`abc`) are present before the declared CONNECT frame end
- Purpose: negative case distinguishing whole-frame bounds validation from
  inner CONNECT field bounds; it exercises a length-delimited field exceeding
  frame bounds
- Future expected PFL behavior: one normal TCP Flow, Detected Protocol must
  not be `MQTT`, empty service hint
- Current pre-implementation PFL behavior: ordinary TCP
- Wireshark note: may present this as malformed MQTT

## Intentionally Omitted Permanent Fixtures

This first fixture set intentionally omits permanent PCAPs for:

- every malformed MQTT Variable Byte Integer permutation;
- five-byte Remaining Length;
- Variable Byte Integer overflow variants;
- non-minimal Variable Byte Integer variants;
- invalid Will QoS combinations;
- Will Retain without Will Flag;
- split-across-TCP CONNECT;
- CONNACK-only, PUBLISH-only, PINGREQ-only, SUBSCRIBE, DISCONNECT, or AUTH
  flows;
- MQTT over TLS;
- TLS on TCP/8883;
- MQTT over WebSockets;
- MQTT-SN.

Those are either better synthetic unit-test boundaries, future protocol-depth
work, existing TLS concerns, or known first-pass limitations that should not
become permanent negative product contracts.

## Future Parsing Boundary

These fixtures define only the target first MQTT detection-only behavior.
Future MQTT work may add deeper packet parsing, topic extraction, QoS
statistics, session state, protocol-aware Stream rows, or MQTT-specific Packet
Summary presentation, but those capabilities are outside this fixture
contract.

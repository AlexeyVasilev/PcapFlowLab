# Index v15 Container RFC

Status: proposed design / RFC only.

This document defines the proposed container-level baseline for a future index
v15 format.

This RFC does not implement index v15, does not change the current index
version, and does not require a compatibility loader for v14 and earlier.

Related RFCs:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)
- [Flow Aggregate Metadata RFC](flow-aggregate-metadata-rfc.md)

## Goal

Starting with index v15, a future Pcap Flow Lab version should be able to read
the stable index preamble/header and report useful metadata even if it cannot
load the analysis payload.

The new compatibility contract starts at v15.

v14 and earlier may remain unsupported.

## Current State

### Current v14 top-level structure

Verified from current code:

- file starts with:
  - `u64 kCaptureIndexMagic`
  - `u16 kCaptureIndexVersion`
  - `u16 reserved`
- current version constant is `kCaptureIndexVersion = 14`
- after the fixed preamble, the file contains length-delimited sections:
  - `u32 section_id`
  - `u64 payload_size`
  - raw payload bytes

Current section families are:

- `source_info`
- `summary`
- `protocol_paths`
- `ipv4_connections`
- `ipv6_connections`
- `unrecognized_packets`
- `packet_locator`

### Current reader behavior

Verified current behavior:

- reader checks exact `magic`
- reader checks exact `version == kCaptureIndexVersion`
- if version mismatches, it fails immediately with:
  - `"unsupported index version; rebuild the index from the source capture"`
- it does not attempt graceful stable-header introspection for newer versions
- unknown section ids are rejected immediately
- all current known sections are effectively required by the reader

### Current source metadata availability

Current source metadata already exists as `CaptureSourceInfo` and contains:

- source capture path
- source format
- source file size
- source last-write time
- source content fingerprint

However, in v14 this metadata is stored in a normal later section rather than a
separately readable stable header. A version mismatch prevents the reader from
reaching it.

## Proposed v15 Baseline

v15 should establish a stable self-describing container design.

The main compatibility rule is:

- a future reader may reject unsupported analysis payload sections
- but it should still be able to read and report stable header metadata

At minimum, a future reader should be able to determine:

- this is a Pcap Flow Lab index
- container format version
- index/schema revision
- writer application version
- source capture path/name
- source capture format
- source capture file size
- source last-write metadata if retained
- source fingerprint/identity if retained

## Proposed Conceptual Layout

### Stable preamble/header

Conceptual header fields:

- magic
- `container_format_version`
- `header_size`
- `index_schema_revision` or `index_revision`
- writer application version
- stable source metadata
- room for append-only future header extensions

### After the stable header

The payload should be organized as versioned length-delimited sections.

Each section should conceptually contain:

- section id
- section schema version
- flags
- payload size
- payload

This keeps unknown/optional data skippable and known data explicitly versioned.

## Required vs Optional Sections

### Required section semantics

Required sections are necessary to interpret the analysis payload correctly.

If a required section is missing or has an unsupported schema version:

- analysis payload loading should fail cleanly
- stable header metadata should still remain available for diagnostics

### Optional section semantics

Optional sections can be skipped safely when unknown or unsupported.

Desired behavior:

- unknown optional section -> skip by payload size
- known supported section version -> read
- unsupported optional section version -> ignore if safe to do so

## Compatibility Contract Starting At v15

The proposed long-term compatibility model is:

- stable header is the guaranteed introspection surface
- payload compatibility is determined mainly by required section schema versions
- a global index/container revision may remain useful for diagnostics and broad
  format families, but not as the sole compatibility gate

This means future revisions do not need universal full backward compatibility.

The important improvement is controlled section-level compatibility and better
diagnostics.

## Proposed Failure Behavior

When the reader cannot load the analysis payload:

- it should still report stable source metadata from the header
- it should explain which required section or required section schema version is
  unsupported
- it should not fail with only a generic exact-version rejection when header
  metadata is still readable

Examples of useful diagnostics:

- recognized Pcap Flow Lab index container
- writer application version
- source capture path / format / size
- unsupported required section id
- unsupported section schema version

## Header Size And Append-Only Extension

`header_size` is useful because it allows:

- a reader to skip forward to the first section even if the stable header grows
- append-only extension of header fields in later revisions
- preservation of the stable preamble contract while allowing new stable header
  metadata to be added in a controlled way

## Current v14/v15 Boundary

This RFC explicitly does not require:

- a v14 -> v15 compatibility loader
- automatic rewriting of old indexes
- support for all historical index revisions

For v14 and earlier, current behavior may remain:

- exact-version rejection
- or a generic legacy-version rejection

The new compatibility/introspection contract begins at v15.

## Current-State Gaps This RFC Intends To Fix

The current v14 format has these issues:

- exact global version gating happens before source metadata can be read
- unknown sections are always fatal
- section payloads have ids and sizes but no explicit per-section schema
  versions
- there is no stable header-level writer application version
- there is no stable header-level source metadata contract

## Proposed V1 Section Families

The exact v15 section list is still open, but a plausible first family is:

- source-info / source-identity section
- summary section
- protocol-path registry section
- IPv4 connection data section
- IPv6 connection data section
- unrecognized-packet section
- packet-locator section

The key change is not the list itself; it is the container contract around
stable header introspection plus per-section schema/version handling.

## Open Questions

- Should `container_format_version` and `index_schema_revision` both exist, or
  is one of them redundant if section-schema versions are authoritative?
- Should the writer application version be stored as:
  - semantic string
  - packed integer tuple
  - both?
- Which source identity fields belong in the stable header versus an optional
  source-details section?
- Should the stable header include a short source capture basename separately
  from full path to improve diagnostics across platforms?
- Should connection-data sections be further subdivided in v15, or remain large
  coarse-grained sections with their own schema versions?
- Should required/optional section semantics use an explicit flag bit in the
  section header, or should requirement be implied by section id family?
- Should the packet locator remain required for v15, or can it become optional
  if certain features degrade gracefully without it?

## Risks To Resolve Before Production Implementation

- If the stable header is underspecified, v15 may still force future versions
  into broad exact-version rejections.
- If section compatibility rules are unclear, optional/required handling can
  become inconsistent across reader implementations.
- If source metadata is split awkwardly between stable header and sections,
  diagnostics may remain incomplete in partial-compatibility scenarios.
- If global revision and per-section schema versions overlap ambiguously, future
  migrations will be harder to reason about.

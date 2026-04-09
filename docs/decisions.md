# Decisions

This document records short, stable architectural decisions for Pcap Flow Lab.

## Core architecture

- Fast path is packet-oriented and bounded.
- No global reassembly runs during capture open.
- Index files do not store raw payload bytes or Stream artifacts.

## Stream

- Stream is selected-flow only.
- Stream is on-demand and ephemeral.
- Stream reassembly is bounded and heuristic.
- Stream is not TCP-correct reconstruction.

## Analysis

- Analysis is selected-flow only.
- No global analysis or precompute runs during open.
- Analysis follows a metadata-first approach.
- Analysis results are not persisted.

## UI / scalability

- Large lists use virtualization rather than pagination by default.
- Selected-flow packet and Stream loading must stay bounded and incremental.

## Protocol handling

- Conservative parsing is preferred over aggressive classification.
- QUIC parsing is bounded and phased rather than globally deep by default.
- `Possible TLS` and `Possible QUIC` are weak hints, not confirmed detection.

## Current active direction

- Stream baseline tests are fixture-backed.
- HTTP reassembly supports `Content-Length` and chunked-body traversal for Stream continuity.
- Retransmission detection and exact duplicate suppression are selected-flow only.
# Roadmap

## Phase 1: Architecture and Bootstrap

- Establish repository structure
- Define core domain model skeleton
- Add baseline build and test setup

## Phase 2: PCAP Reader and Packet Index

- Implement classic PCAP reader
- Add packet metadata extraction
- Build persistent packet offset index

## Phase 3: Flow Aggregation and Query API

- Aggregate packets into normalized bidirectional flows
- Add session query interfaces
- Expose summary and lookup services

## Phase 4: CLI

- Add command-line workflows for opening captures and listing flows
- Support summary and detail queries

## Phase 5: Desktop UI

- Build a separate desktop frontend on top of the application layer
- Keep UI logic independent from capture processing internals

## Phase 6: Protocol Enrichment and Exports

- Add layered protocol enrichment
- Support structured export flows and reports

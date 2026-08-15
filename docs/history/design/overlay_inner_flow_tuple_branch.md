# Overlay Inner Flow Tuple Branch

## Status

Status: superseded historical branch design.

This document records the original branch-era design for VXLAN, Geneve, and
GTP-U inner-tuple flow grouping. Those protocols are now implemented, and the
current production architecture has moved beyond several of the original branch
assumptions.

Current authoritative documents are:

- `docs/protocols/protocol_support.md`
- `docs/protocols/protocol_path_flow_identity.md`
- `docs/architecture.md`

## Historical goal

The original branch goal was to support common encapsulation protocols that sit
above outer UDP and carry an inner IPv4/IPv6 plus TCP/UDP/SCTP packet, so the
product could build flows from the effective inner tuple.

That original motivation remains useful historical context:

- effective inner tuples were needed to make overlay traffic analyzable as the
  inner conversation rather than as outer carrier UDP shells;
- strict flow extraction and lenient selected-packet presentation were already
  understood as separate concerns;
- carrier metadata and inner semantics needed to coexist without pretending
  they were the same thing;
- fixture-first implementation was the right engineering strategy.

## What changed after this branch

The current implementation supersedes several branch-era assumptions.

Verified current architectural changes include:

- raw-capture import is now driven by the unified registry-driven dissection
  engine rather than by treating `PacketDecoder::decode(...)` as the
  authoritative import grouping path;
- canonical recognized-flow identity now includes `ProtocolPathId`;
- namespace-bearing protocol-path identifiers now split flows where available,
  including:
  - VXLAN VNI
  - Geneve VNI
  - GTP-U TEID
  - GRE key
- current support and limitations are documented in the protocol-support and
  protocol-path flow-identity documents rather than in this branch note.

## Historical branch-era limitations

The original branch intentionally accepted an inner-tuple-first limitation:

- traffic from different overlay namespaces could merge when only the deepest
  inner tuple was used;
- VNI/TEID-aware identity had not yet been added;
- outer tunnel endpoints were not part of the first identity model.

That historical limitation should be preserved here as design history.

Current follow-up reality is different:

- Protocol Path identity now includes namespace-bearing identifiers such as
  VXLAN VNI, Geneve VNI, GTP-U TEID, and GRE key;
- outer carrier endpoints are still intentionally excluded from the current
  v1 identity model, so some same-namespace same-inner-tuple traffic can still
  merge across different outer carriers.

## Historical recommendations that are no longer current guidance

The branch document originally discussed recommendations such as:

- inserting overlay tuple extraction into `PacketDecoder::decode(...)`;
- not making VNI/TEID part of flow identity yet;
- keeping GRE key outside identity;
- referring to selected-packet `Summary / Protocol details` terminology.

These points must now be read strictly as branch-era design history.

They are superseded by current production facts:

- import/open flow construction is owned by unified dissection;
- Protocol Path identity already includes VXLAN VNI, Geneve VNI, GTP-U TEID,
  and GRE key;
- current selected-packet and selected-flow terminology is no longer
  `Protocol details` as a visible UI surface.

## Historical rationale worth preserving

The following branch-era reasoning remains valuable historical background:

- why inner flow grouping was needed in the first place;
- why strict extraction should stay separate from best-effort selected-packet
  presentation;
- why tunnel carrier metadata should remain visible even when the effective
  grouped flow comes from the inner transport tuple;
- why deterministic fixtures were important before broadening overlay support.

## Current role

This file should not be used as current implementation guidance.

It should be used only as:

- branch history;
- original rationale for the overlay tuple work;
- background for how later Protocol Path identity evolved.

## Recommended future location

This file is a strong candidate for later relocation to:

- `docs/history/branches/`

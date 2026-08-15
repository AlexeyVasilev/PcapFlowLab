# UI Improvement Backlog

## Status

Status: living engineering backlog.

This document tracks UI polish and workflow improvements that remain
meaningfully open after the recent correctness and selected-flow stabilization
work. It is not a product contract.

Current presentation semantics remain defined by:

- `docs/ui/presentation_contract.md`

## Scope

This backlog is intentionally UI-focused.

It should not be used to track:

- parser architecture;
- protocol-roadmap work;
- PacketRef compaction;
- flow-identity redesign;
- other backend refactors that are not primarily UI improvements.

## Current strengths already in place

The current desktop UI already has several improvements that are no longer
backlog items by themselves:

- Packet Details uses `Summary` and `Bytes`;
- Stream Item Details uses `Summary` and `Item Data`;
- no visible Protocol tab remains in those surfaces;
- selected-flow packet, stream, and details workflow is materially clearer than
  earlier iterations;
- Statistics and Settings terminology are more consistent than before;
- copy actions and helper affordances exist for several repeated workflows such
  as Wireshark filter copying and byte export.

## Active backlog

### High priority

**1. Active: denser packet and stream pane layout**  
Problem: Dense workflows still lose space to padding, large gaps, and
low-value separators.  
Why it remains open: The application is more usable than before, but dense
inspection sessions still leave visible room for compaction in list and detail
regions.  

**2. Active: better truncation with full-value access**  
Problem: Long paths, hostnames, SNI values, packet lists, and protocol-path
text can still be hard to inspect cleanly.  
Why it remains open: Some copy/tooltip affordances exist, but truncation
behavior is not yet fully standardized across Qt and Tauri.  

**3. Partially addressed: stronger hierarchy in details text blocks**  
Problem: Packet and stream details are much better than earlier versions, but
long TLS/QUIC/HTTP detail regions can still flatten visually.  
Why it remains open: The core structure is in place; further sectioning and
typography polish remain useful.  

**4. Partially addressed: better visibility of packet truth vs stream truth**  
Problem: The current surfaces are semantically correct, but users can still
confuse packet-selected truth with selected-flow semantic truth.  
Why it remains open: Current tabs and wording are better, yet compact reminder
text and surface labeling can still improve.  

**5. Active: smarter `Load more` and bounded-analysis messaging**  
Problem: Partial selected-flow analysis is correct, but bounded-window state
can still be undersold or too subtle.  
Why it remains open: The UI already indicates loading and boundedness, but
there is still room to explain what additional loading may change without
turning the surface into warning noise.  

### Medium priority

**6. Partially addressed: faster copy and reference actions in analyst workflows**  
Problem: Repeated analyst work still benefits from quicker copying of selected
packet/stream references, detail values, filters, and related context.  
Why it remains open: Some high-value copy actions already exist, but broader
workflow coverage is still incomplete.  

**7. Active: top workspace density and context clarity**  
Problem: The top workspace area carries active-session context, filters, and
helper values, but it can still be denser and easier to scan.  
Why it remains open: Recent passes improved session/status presentation, yet
cross-platform header density and overflow behavior still need polish.  

**8. Active: better marker visibility without selection-like noise**  
Problem: Special packet conditions are useful, but markers can still be missed
in dense views.  
Why it remains open: This remains an open presentation problem rather than a
backend gap.  

**9. Partially addressed: more consistent naming across panes and menus**  
Problem: Major terminology mismatches were cleaned up, but some cross-surface
wording can still be normalized further.  
Why it remains open: Terminology is much healthier now, but smaller wording
drift can still accumulate.  

**10. Active: stronger empty and unavailable states**  
Problem: Some empty, unavailable, partial, or source-capture-missing panes can
still feel too visually similar.  
Why it remains open: The state model is present, but compact and consistently
helpful wording remains worth refining.  

**11. Partially addressed: selection continuity across related views**  
Problem: Selection changes across flows, packets, stream items, and tabs are
more stable than before, but small context-loss moments still occur.  
Why it remains open: The core continuity rules improved, yet the workflow can
still be tightened further.  

**12. Active: more compact ownership presentation for large reassembled items**  
Problem: Ownership and packet-contribution context are valuable, but long packet
lists can become noisy in dense views.  
Why it remains open: The shortened ownership approach exists, but additional
presentation refinement remains useful.  

**13. Deferred: keyboard-oriented analyst workflow improvements**  
Problem: Repeated analyst workflows still lean heavily on pointer movement.  
Why it is deferred: Basic shortcuts/focus behavior exists, but a broader
keyboard-navigation pass is still a distinct workflow project rather than a
small polish task.  

### Lower priority

**14. Active: unified control and pane styling pass**  
Problem: The desktop surfaces still show some framework-specific visual
inconsistency across panes, buttons, inputs, and cards.  

**15. Active: cleaner typography hierarchy**  
Problem: Headers, metadata, helper text, and dense table content can still use
more consistent emphasis rules.  

**16. Active: modernized status, badge, and tab appearance**  
Problem: Status indicators and secondary UI chrome still have polish headroom,
even after recent cleanup passes.  

**17. Active: better visual treatment of analysis-tool-specific metadata**  
Problem: Ownership, direction, partial-state, and protocol-specific hints are
important but not always visually prioritized as clearly as they could be.  

## Suggested sequence

1. Continue with compact density and truncation improvements first.
2. Refine bounded-state, empty-state, and packet-vs-stream wording next.
3. Follow with copy/reference and selection-continuity polish.
4. Do a restrained cross-platform styling pass after the workflow issues above.

## Recommended future treatment

Keep this document in the current docs tree while it remains a live backlog.

If a later inventory pass finds that most of these items are fully addressed,
the document can then be retired or replaced with a smaller active backlog.

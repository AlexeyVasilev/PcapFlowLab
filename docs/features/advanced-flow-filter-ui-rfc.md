# Advanced Flow Filter UI RFC

Status: design-only RFC for the future Advanced Flow Filter user interface.

This document records the currently agreed UI design for Advanced Flow Filter.
It is intentionally limited to UI/document-state behavior and implementation
staging. It does not change the backend filter model, `AdvancedFlowFilterSpec`,
CLI behavior, or current Qt/Tauri behavior.

The backend semantic reference remains:

- [Advanced Flow Filter RFC](advanced-flow-filter-rfc.md)

## Scope And Boundary

This RFC is the UI source of truth for later implementation passes.

Agreed here:

- Flows-page mode switching between Simple Filter and Advanced Filter
- Advanced Filter document/state model
- Advanced Filter settings window concept
- agreed editor interaction patterns for current and near-term predicate families
- validation and rule-count presentation
- staged implementation direction

Still deferred here:

- exact Qt implementation staging details
- Tauri parity details
- final styling and polish
- dedicated capture-level count-summary architecture
- exact future `.filter` grammar for persisted section Enabled state
- exact mapping/API between Protocol Path UI modes and backend match shapes
- exact implementation structure for configured document state versus effective
  enabled spec

## Design Principles

- Simple Filter and Advanced Filter are separate modes and are never applied
  together.
- The normal Flows table width must be preserved; the full Advanced Filter
  editor is not shown beside the flow table.
- Editing uses an explicit draft model so users can cancel without losing the
  applied filter.
- The UI must not trigger a full-flow scan merely to populate editor counts.
- The UI should expose backend semantics clearly without forcing users to edit
  `.filter` syntax directly.

## Filter Modes

The Flows page has two mutually exclusive filtering modes:

- Simple Filter
- Advanced Filter

Simple mode toolbar concept:

```text
[ Filter by protocol, hint, service, address or port... ]
[ Use advanced filter ]
[ Clear ]
```

Advanced mode toolbar concept:

```text
[ Settings ]
[ Filter: <display name> ]
[ N rules ]
[ Use simple filter ]
[ Clear ]
```

Rules:

- Simple and Advanced filters are never applied together.
- Switching mode does not destroy the inactive filter state.
- Returning from Advanced mode to Simple mode restores the previous simple-text
  filter state.
- Returning from Simple mode to Advanced mode restores the previous applied
  Advanced Filter state.

## Advanced Filter Display Name

A newly created Advanced Filter is displayed as:

```text
Custom filter
```

A filter loaded from a file uses the filename/basename as its display name.

Examples:

- `tls_1_3_big`
- `customer_a_udp`

If a file-backed filter is modified after save, the displayed name uses a dirty
marker, for example:

```text
tls_1_3_big *
```

The compact user-facing display name for a file-backed filter uses the source
file stem without the `.filter` extension.

Notes:

- The full file path may be shown through a tooltip.
- The stable `.filter` format must not gain a UI-only filter-name field.

## Filter Document State

The conceptual Advanced Filter UI document model distinguishes configured
document state from the effective backend filter spec.

Configured filter document contains:

- all configured predicates, including predicates retained inside disabled
  sections
- section Enabled states
- optional source file path
- saved baseline
- dirty state

Effective `AdvancedFlowFilterSpec`:

- is derived from the configured document
- contains only predicates from enabled sections
- is the filter that is compiled/evaluated

Draft:

- is an editable configured-document state while Settings is open

Three conceptual states must be distinguished:

- Saved
- Applied
- Draft being edited

Behavior:

- Opening Settings creates or resumes a draft.
- Apply validates the current draft, derives the effective
  `AdvancedFlowFilterSpec`, and applies it.
- Cancel discards only the current draft and preserves the applied filter.
- Applying a modified file-backed filter keeps it associated with the source
  file path but marks it dirty until saved.
- Saving establishes a new saved baseline and clears dirty state.
- Switching between Simple and Advanced mode does not prompt to save.
- Prompting about unsaved changes is reserved for cases where the document
  would actually be lost, such as opening another filter over dirty state or
  closing the application.

This means Advanced Filter UI behavior is document-oriented, but mode switching
alone is not document-destructive.

Protocol Path and Contains Layer are independently Enabled sections in the
configured document.

Today they map onto different match shapes within the existing backend
protocol-path predicate family.

Disabling Protocol Path must not implicitly disable Contains Layer, and
disabling Contains Layer must not implicitly disable Protocol Path.

## Settings Window

Advanced Filter settings are edited in a separate large window or dialog.

The full editor must not be embedded beside the flow table.

Rationale:

- the flow table should retain its normal width
- the filter editor needs enough space for repeated structured rule rows
- keeping editing separate avoids collapsing the core Flows-page layout

Conceptual layout:

```text
[ Open filter... ] [ Clear unsaved changes ]      [ Save ] [ Save As... ]

Filter: Custom filter / filename / filename *

filter sections...

[ Clear all ]                              [ Cancel ] [ Apply ]
```

Current agreed behavior:

- `Apply` initially means apply and close
- this may be revisited later during UI testing
- exact spacing/styling remains polish

### Open Filter

`Open filter...` loads another `.filter` document.

If replacing the current filter would lose unsaved configuration, the UI must
prompt before replacement.

Conceptual choices for a file-backed modified filter:

- Save
- Discard
- Cancel

For an unsaved Custom filter with configured rules:

- Save As
- Discard
- Cancel

The UI must not prompt merely because the current filter has capture-specific
applicability warnings. Applicability warnings are transient and are not dirty
document state.

A read/parse/validation failure leaves the current configured document, applied
filter, source association, and dirty state unchanged.

A successfully opened filter becomes the current filter and is applied.

Protocol Path / Contains Layer rules that are valid filter rules but are not
present in the current capture do not make Open fail.

Instead, the filter is loaded and applied, and the already-agreed contextual
applicability warnings are shown.

If replacement was requested after choosing Save, replacement occurs only after
that save succeeds.

### Clear Unsaved Changes

`Clear unsaved changes` is intended for a file-backed filter that differs from
its saved baseline.

The button is active only when:

- the current Advanced Filter is associated with a source `.filter` file
- the current configuration has unsaved changes relative to that saved file

While Settings is open, this means the current editor draft differs from the
saved baseline.

Outside an active Settings edit session, dirty state is based on the applied
configured document versus saved baseline.

It is disabled when:

- the filter is a Custom filter with no saved baseline
- a file-backed filter exactly matches its saved baseline

Action semantics:

- discard the current unsaved configuration
- restore the last saved baseline
- restore saved section Enabled states as well once the format persists them
- apply the restored saved configuration
- clear the dirty marker
- do not modify the file on disk

This explicit action does not require an additional confirmation dialog.

If the Settings window contains draft edits, the restored saved baseline must
also become the current editor state so `Cancel` cannot unexpectedly resurrect
the discarded dirty configuration.

### Save

`Save` and `Apply` are separate user concepts, but Settings must not create an
ambiguous saved-versus-active state.

Agreed Save behavior:

- validate the current draft
- make that validated draft the current applied filter
- write the current filter document to its existing source path
- clear dirty state after successful save
- keep the Settings window open

If validation or writing fails, the UI must not clear dirty state or pretend
the save succeeded.

For a Custom filter without a source path, `Save` behaves as `Save As...`.

Save must preserve the entire configured filter document, including disabled
sections once the `.filter` format supports section Enabled state.

### Save As

`Save As...`:

- validates the current draft
- asks for a new `.filter` path
- makes the validated draft the current applied filter
- saves the full configured document to the chosen path
- associates the current document with that new source path
- updates its display name from the filename/basename
- clears dirty state after successful save
- keeps the Settings window open

Cancelling the file chooser changes nothing.

If validation or writing fails, the UI must not bind the new source path or
clear dirty state.

The UI does not introduce a separate embedded filter-name field solely for
Save As.

### Apply

`Apply`:

- validates the current draft
- converts the configured document plus section Enabled states into the
  effective Advanced Filter
- applies it to the flow list
- updates dirty state relative to the saved baseline
- closes the Settings window

If the applied configuration differs from the saved file, the file-backed
display name receives the dirty marker:

```text
filter_name *
```

Capture-specific applicability changes do not create dirty state.

### Cancel

`Cancel`:

- discards ordinary draft edits made since the current applied editor state
- preserves the currently applied Advanced Filter
- closes the Settings window

Closing the Settings window through its normal window-close affordance may be
treated like Cancel.

The UI does not add an unnecessary confirmation dialog for normal Cancel
behavior.

### Clear All

`Clear all` is destructive to the current configured Advanced Filter document.

After successful Clear all:

- all configured predicates are removed
- all section-specific retained rule configuration is removed
- the current source-file association is removed
- the document becomes:

```text
Custom filter
```

- active rule count becomes 0
- the effective Advanced Filter is empty
- the source `.filter` file on disk, if any, is not modified

This is not equivalent to disabling every section.

The UI does not retain hidden disabled rules after Clear all.

### Clear All Confirmation Policy

The UI prompts only when Clear all would destroy configuration that is not
safely recoverable from the current saved file.

Cases:

1. Clean file-backed filter

```text
Filter: tls_big
dirty = false
```

Clear all may proceed without confirmation because the original configuration
remains recoverable from `tls_big.filter` on disk.

Result:

```text
Custom filter
0 rules
```

2. Dirty file-backed filter

```text
Filter: tls_big *
```

Clear all must prompt because unsaved changes would be lost.

Conceptual choices:

- Save and clear
- Discard and clear
- Cancel

3. Non-empty Custom filter

Clear all must prompt because the configured filter has never been saved.

Conceptual choices:

- Save As and clear
- Discard and clear
- Cancel

4. Empty Custom filter

No confirmation is required.

The exact dialog wording/styling may be polished later, but this loss-based
confirmation rule is agreed.

If the destructive flow offers `Save and clear` or `Save As and clear`, the
clear operation happens only after the save succeeds.

If Save/Save As is cancelled or fails, the filter is not cleared.

### Main Flows Toolbar Clear

The Advanced-mode `Clear` button in the main Flows toolbar uses the same
destructive operation and confirmation policy as `Clear all` in Settings.

Conceptual toolbar:

```text
[ Settings ] [ Filter: tls_big * ] [ N rules ]
[ Use simple filter ] [ Clear ]
```

Clear:

- clears to `Custom filter` / `0 rules`
- removes source association
- does not modify the old source file on disk
- prompts only when unsaved configuration would otherwise be lost

The UI does not implement a separate toolbar-specific Clear semantic.

### Unsaved Configuration Concept

This RFC distinguishes display dirty state from recoverability.

File-backed filter:

```text
tls_big
    saved/clean

tls_big *
    unsaved changes relative to saved baseline
```

Custom filter:

- the UI does not require a visible `*` marker

However, the UI internally distinguishes:

- `Custom filter` + 0 configured rules
  - no meaningful unsaved configuration
- `Custom filter` + configured rules
  - unsaved configuration exists

This internal distinction drives destructive-action prompts even though the
toolbar display remains simply:

```text
Custom filter
```

A newly created Custom filter has:

- 0 configured predicates
- 0 active rules

Clear all returns to the same empty Custom-filter state.

Default empty-state semantics:

- finite predicate checkboxes are unchecked by default
- repeatable rule collections are empty by default
- numeric Minimum/Maximum inputs are empty by default
- an Enabled section with no configured predicates contributes no rule
- section Enabled controls may default to enabled, but Enabled by itself is not
  a predicate and does not increase the rule count

### Draft / Applied / Saved Consistency

The existing Saved / Applied / Draft model remains in force.

File actions must not create a confusing long-lived state where the file
contains one configuration while a different configuration remains active only
because Apply was not pressed.

Therefore Save / Save As first validate and accept the current draft as the
active document, then persist it.

Conceptual action semantics:

```text
Apply:
    validate
    apply draft
    update dirty state
    close Settings

Save:
    validate
    apply draft
    save to current path
    dirty = false
    keep Settings open

Save As:
    validate
    choose path
    apply draft
    save to new path
    bind path
    dirty = false
    keep Settings open

Cancel:
    discard current ordinary draft edits
    close Settings

Clear unsaved changes:
    restore saved baseline
    apply restored baseline
    dirty = false

Clear all:
    destructively replace the current document with empty Custom filter,
    subject to the agreed loss-confirmation policy
```

## Include / Exclude Visual Pattern

For finite checkbox categories, the default interaction pattern is:

- show Include values directly
- keep Exclusions hidden by default behind an expansion affordance

Example:

```text
Flow protocol

[x] TCP
[ ] UDP
[ ] SCTP

[ + Exclusions ]
```

Expanded concept:

```text
Include
...

Exclude
...

[ - Hide exclusions ]
```

This interaction is used consistently for finite enum-like categories.

Semantic mapping:

- multiple include predicates within one category use OR
- any matching exclusion rejects the flow
- different categories combine with AND

## Counts Policy

Counts such as:

- `TLS 1.2 (482)`
- `TLS 1.3 (37)`
- `Unknown TLS/SSL (916)`

can be useful in checkbox categories, but the settings UI must never trigger a
full scan of the flow inventory merely to calculate them.

Agreed policy:

- counts may be displayed only when they are already available from ready
  capture-level summary/statistics metadata
- the initial UI must not calculate arbitrary port, IP, CIDR, or service counts
  when opening the dialog
- when capture-level counts are not available for a category, the initial UI
  omits counts for that category

Future note:

- a dedicated capture-level filter-value summary may be added later if needed

## Address Family

Planned checkbox UI:

```text
Address family

[ ] IPv4
[ ] IPv6

[ + Exclusions ]
```

Current status:

- this is agreed UI design
- this is a conceptual non-default example and not the initial new-filter state
- the backend `AdvancedFlowFilterSpec` does not yet expose a dedicated address
  family predicate
- therefore address family is a small backend prerequisite before full UI
  implementation

This RFC records the dependency but does not implement it.

## Flow Protocol

The UI uses the existing Flow Protocol concept.

There is no separate redundant "Transport protocol" category.

Representative values include:

- TCP
- UDP
- SCTP
- ICMP
- ICMPv6
- IGMP
- ARP
- ESP
- others represented by the shared backend flow-protocol model

Interaction:

- checkbox Include values
- expandable Exclusions

## Detected Protocol

Detected Protocol uses checkbox Include values with expandable Exclusions.

The values come from current `FlowProtocolHint` semantics.

Examples include current product concepts such as:

- TLS
- HTTP
- DNS
- QUIC
- SSH
- SMTP
- mDNS
- Possible TLS
- Possible QUIC
- Unknown

This RFC does not redefine backend hint semantics; it only records the agreed
UI pattern.

## TLS And QUIC Version

TLS and QUIC versions use checkbox-based interaction.

Conceptual labels:

- TLS 1.2
- TLS 1.3
- Unknown TLS/SSL
- QUIC v1
- QUIC v2
- QUIC draft-29
- Unknown QUIC

Counts may be shown only under the capture-level-count policy described above.

## Directionality

Directionality uses the same checkbox Include plus expandable Exclusions
pattern.

Values are exactly:

- Unidirectional
- Bidirectional

This UI must not reintroduce:

- Any
- A-to-B-only
- B-to-A-only

That aligns with the current backend directionality model for listable flows.

## Port Editor

Ports use repeatable structured rows rather than enum checkboxes.

Each row contains:

- Scope:
  - Either endpoint
  - Endpoint A
  - Endpoint B
- Range checkbox
- numeric input(s)
- remove action

Conceptual single-port row:

```text
[ Either endpoint ] Range [ ] Port [443] [x/remove]
```

Conceptual range row:

```text
[ Either endpoint ] Range [x] From [8000] To [9000] [x/remove]
```

Rules:

- the `To` field is hidden when Range is disabled
- if the user previously entered a `To` value in the current draft, that hidden
  draft value is preserved when Range is toggled off so temporarily turning
  Range off and back on does not destroy user input
- only the currently active exact-port or range form is mapped into the applied
  spec
- new rows default to:
  - Either endpoint
  - Range off
  - empty Port
- allowed port range is `0..65535`
- ranges require `From <= To`
- include rows use OR
- exclusions are hidden by default behind `[ + Exclusions ]`
- exclusion rows reuse the same editor pattern
- an empty Include set plus Exclusions is valid
- the UI must not calculate flow counts for arbitrary port rules

## IP And CIDR Editor

IP rules use the same general interaction model as Ports.

Each rule contains:

- Scope:
  - Either endpoint
  - Endpoint A
  - Endpoint B
- Subnet checkbox
- Address
- optional Prefix
- remove action

Conceptual exact-address row:

```text
[ Either endpoint ] Subnet [ ] Address [192.168.1.10]
```

Conceptual subnet row:

```text
[ Endpoint B ] Subnet [x]
Address [10.0.0.0]
Prefix [8]
```

Rules:

- exact addresses do not require `/32` or `/128`
- the UI detects IPv4 vs IPv6 from the entered address
- IPv4 prefix range is `0..32`
- IPv6 prefix range is `0..128`
- when Subnet is toggled off, the Prefix field is hidden
- if the user previously entered a Prefix value in the current draft, that
  hidden draft value is preserved when Subnet is toggled off so temporarily
  turning Subnet off and back on does not destroy user input
- only the currently active exact-address or subnet form is mapped into the
  applied spec
- if a subnet address has host bits set, the UI should not silently rewrite the
  typed address while the user is editing
- the UI may optionally show normalized information such as:

```text
Network: 192.168.1.0/24
```

- the initial UI does not need convenience parsing like `10.0.0.0/8` inside
  the Address field
- the Subnet checkbox and Prefix field remain explicit
- include rules use OR
- exclusion rules reuse the same editor pattern and are hidden by default
- the UI must not calculate arbitrary IP/CIDR counts when opening the dialog

## Service Editor

Service filtering uses one Include section containing:

- state checkboxes:
  - Known
  - Unknown
- repeatable text rules

Supported text operators:

- Equals
- Starts with
- Contains

Each text rule contains:

- operator
- Case sensitive checkbox
- value
- remove action

Example:

```text
[ Contains ] Case sensitive [ ] [youtube.com] [remove]
```

Mapping rules:

- unchecked Case sensitive maps to current ASCII case-insensitive semantics
- checked Case sensitive maps to case-sensitive semantics
- the GUI accepts a plain text value and does not require `.filter` quoting or
  escaping syntax
- text rules are OR within the Service include family
- state and text include predicates follow the current backend OR semantics
- exclusions are hidden by default using the same `[ + Exclusions ]` pattern
- exclusion state/text rules use equivalent controls

Initial non-goals:

- no regex
- no arbitrary service-rule counts

## Protocol Path

Protocol Path and Contains Layer are two distinct UI sections.

The UI must not expose one generic protocol-path rule editor with user-facing
`Exact` / `Prefix` / `Contains` modes.

The two concepts have different responsibilities:

- Protocol Path
- Contains Layer

Protocol Path selects a structural path from the current capture's Protocol
Path statistics model.

Contains Layer matches the presence of an identifier-bearing intermediate or
encapsulation layer.

### Protocol Path Section

Conceptual section:

```text
Protocol Path                              Enabled [x]

Include

<selected path rule>                       [ Edit ] [ remove ]

[ + Add path ]

[ + Exclusions ]
```

Exclusions use the same selected-path rule representation and are hidden by
default according to the existing Include / Exclusions interaction model.

Multiple enabled Include Protocol Path rules use the existing OR semantics.
Any matching enabled exclusion rejects the flow.

### Add And Edit Protocol Path Picker

Pressing:

- `[ + Add path ]`
- `[ Edit ]`

opens a separate large Protocol Path picker window or dialog.

The picker reuses the same conceptual data and visual language as the existing
Protocol Path Statistics view.

It exposes exactly these three modes:

- Kind overview
- Identity tree
- Terminal paths

The UI does not expose a separate user-facing Prefix mode.

Conceptual picker:

```text
Select Protocol Path

[ Kind overview ] [ Identity tree ] [ Terminal paths ]

Path / Layer                    Flows      Packets      Original Bytes
----------------------------------------------------------------------
Ethernet II
  VLAN
    IPv4
      TCP
      UDP
  MPLS
    IPv4
      UDP
        GTP-U
          IPv4
            TCP
...

                                           [ Cancel ] [ Select ]
```

Rules:

- the Protocol Path tree/list is always fully expanded in this picker
- the UI does not expose Expand all / Collapse all
- the UI does not require per-node expansion interaction
- implementation may still use a flat or virtualized representation where
  appropriate, so "always expanded" does not imply constructing an unbounded
  hierarchy of heavyweight UI controls
- `Select` is enabled only when a valid selectable row is selected
- `Cancel` closes without modifying the draft rule

The picker should reuse existing Protocol Path statistics data/presentation
where practical rather than creating a separate Advanced Filter path-counting
system.

### Protocol Path Picker Mode Semantics

The three modes communicate path semantics through the existing statistics
model instead of user-facing `Exact` / `Prefix` terminology.

Kind overview:

- identifiers are ignored
- selecting a tree node represents the selected structural kind path up to
  that node
- deeper continuation is allowed according to the existing backend path
  matching semantics
- this covers the former user-facing prefix-style use case without exposing a
  Prefix selector

Identity tree:

- identifiers are significant
- selecting a tree node represents the identifier-aware structural path up to
  that node
- deeper continuation is allowed according to the existing backend path
  matching semantics
- this also covers prefix-style use without exposing Prefix terminology

Terminal paths:

- selection represents one complete terminal path
- it matches the complete selected path rather than a structural prefix

The exact mapping from these UI selections into the existing backend
`exact_path` / `path_prefix` representation must be verified during
implementation, but the UI must not expose separate Exact/Prefix controls.

### Protocol Path Picker Data

The picker reuses the same conceptual columns already familiar from Protocol
Path Statistics:

- Path / Layer
- Flows
- Packets
- Original Bytes

The UI must not introduce an Advanced-Filter-specific full-flow scan solely to
populate these values.

Existing cached/statistics-backed Protocol Path information should be reused
where possible.

If implementation reveals that a required statistics mode has a non-trivial
first-use cost, that cost should be evaluated explicitly rather than silently
adding another flow scan to the filter dialog.

### Selected Protocol Path Presentation

After selection, the rule should be represented compactly in Advanced Filter
Settings.

Preferred direction:

- reuse the existing Protocol Path badges or a similarly compact visual
  language already familiar in the product

Conceptual examples:

```text
Kind
[EII] [VLAN] [IPv4]

Identity
[EII] [VLAN 413] [MPLS 73436] [IPv4]

Terminal
[EII] [UDP] [GTP-U TEID ...] [IPv4] [TCP]
```

Each selected rule has:

- its mode/type indication where useful
- compact path presentation
- Edit
- remove

Final styling remains deferred.

### Capture Applicability Of Protocol Path Rules

A valid Protocol Path rule loaded from a `.filter` file may describe a path
that does not exist in the currently opened capture.

This is:

- not a syntax error
- not an invalid filter document
- not a reason to automatically disable the rule

Instead, the UI should show contextual feedback such as:

- `Not present in current capture`
- `Unavailable in this capture`

Example:

```text
Identity
EII | VXLAN VNI 500 | IPv4 | TCP

Warning: Not present in current capture
```

The rule remains enabled unless the user explicitly disables its section.

Rationale:

- a saved filter may intentionally be reused across captures with different
  encapsulation or path populations

### Protocol Path Applicability Semantics

Capture applicability is transient UI/session state.

It is not persisted as part of the filter document.

Opening another capture may change applicability warnings without making the
filter dirty.

An unavailable enabled Include rule simply cannot match that capture.

Existing category OR semantics remain intact.

Example:

- Include Protocol Paths:
  - A
  - B

If A exists in the capture and B does not, then `A OR B` still matches through
A.

If no enabled Include Protocol Path rule can match the capture, the category
may legitimately produce zero matching flows.

The UI must not silently remove unavailable rules from the effective filter,
because doing so could unexpectedly broaden the result.

Unavailable Exclude rules simply match nothing in that capture.

### Protocol Path Applicability Checking

When a filter is loaded and when the active capture changes, the UI may check
Protocol Path rules against the current capture's Protocol Path registry or
statistics model.

This check must not require a new scan over the entire flow inventory solely
for UI validation.

Conceptually:

- Kind overview:
  - check whether the relevant structural kind path exists
- Identity tree:
  - check whether the identifier-aware structural path exists
- Terminal paths:
  - check whether the exact terminal path exists

Exact implementation details may be finalized later.

## Contains Layer

Contains Layer is separate from Protocol Path.

Its purpose is to filter on identifier-bearing intermediate or encapsulation
layers.

The UI does not offer ordinary terminal/basic protocols here when equivalent
dedicated Advanced Filter categories already exist.

Examples that must not be offered in Contains Layer:

- TCP
- UDP
- IPv4
- IPv6
- ICMP
- ARP

Those are covered by Flow Protocol, Address Family, Detected Protocol, or
Protocol Path where structural position matters.

### Contains Layer Eligibility Rule

The conceptual eligibility rule is:

- Contains Layer exposes only Protocol Path layer kinds for which Pcap Flow
  Lab stores a meaningful layer identifier that can participate in a Protocol
  Path predicate

Representative examples include:

- VLAN -> VID
- MPLS -> Label
- PBB -> I-SID
- VXLAN -> VNI
- Geneve -> VNI
- GTP-U -> TEID
- GRE -> Key
- AH -> SPI
- ESP -> SPI

This list should not become a permanently hardcoded UI contract if the backend
already has authoritative layer/identifier metadata that can drive it.

Implementation should avoid UI/backend drift.

### Contains Layer UI

Conceptual section:

```text
Contains Layer                             Enabled [x]

Include

Layer          Identifier
[ VXLAN ▼ ]    [ Any ▼ ]                             [ remove ]
[ VLAN  ▼ ]    [ Exact ▼ ] VID  [ 413 ]             [ remove ]

[ + Add layer ]

[ + Exclusions ]
```

Exclusions are hidden by default and reuse the same row editor.

Each rule has:

- eligible Layer selector
- Identifier mode:
  - Any
  - Exact
- identifier value input when Exact is selected
- remove action

When a layer has a known identifier name, the UI should show the
protocol-specific label rather than generic `Identifier value`.

Examples:

- VLAN -> VID
- MPLS -> Label
- PBB -> I-SID
- VXLAN -> VNI
- Geneve -> VNI
- GTP-U -> TEID
- GRE -> Key
- AH -> SPI
- ESP -> SPI

If Identifier = Any, no value input is required.

### Contains Layer Applicability

Contains Layer rules may also have contextual applicability feedback.

Examples:

```text
VXLAN / Any
Warning: No VXLAN layer is present in this capture.
```

```text
GTP-U / TEID 0x1234
Warning: This TEID is not present in this capture.
```

Such warnings:

- do not make the filter document invalid
- do not automatically disable the rule or section
- are transient capture-specific information only

## Traffic And Numeric Filters

Traffic and numeric predicates are presented as a compact table because they
share the same minimum/maximum range semantics.

Conceptual layout:

```text
Traffic

Value                         Minimum      Maximum      Unit
----------------------------------------------------------------
Packets                       [       ]    [       ]    packets
Original bytes                [       ]    [       ]    [ MiB ▼ ]
Captured bytes                [       ]    [       ]    [ MiB ▼ ]
Duration                      [       ]    [       ]    [ s   ▼ ]

[ + More traffic filters ]
```

The exact visual styling may change later, but the table-oriented interaction
is agreed.

### Common And Additional Filters

Initially visible common rows:

- Packet count
- Original bytes
- Captured bytes
- Duration

Additional less-common rows are hidden behind:

```text
[ + More traffic filters ]
```

Additional rows:

- Maximum original packet size
- Maximum captured packet size
- Fragmented packet count
- Truncated packet count
- TCP SYN count
- TCP FIN count
- TCP RST count

Expanded concept:

```text
Value                         Minimum      Maximum      Unit
----------------------------------------------------------------
Packets                       [       ]    [       ]    packets
Original bytes                [       ]    [       ]    [ MiB ▼ ]
Captured bytes                [       ]    [       ]    [ MiB ▼ ]
Duration                      [       ]    [       ]    [ s   ▼ ]
Maximum original packet size  [       ]    [       ]    [ KiB ▼ ]
Maximum captured packet size  [       ]    [       ]    [ KiB ▼ ]
Fragmented packets            [       ]    [       ]    packets
Truncated packets             [       ]    [       ]    packets
TCP SYN packets               [       ]    [       ]    packets
TCP FIN packets               [       ]    [       ]    packets
TCP RST packets               [       ]    [       ]    packets

[ - Hide additional traffic filters ]
```

If any additional predicate is active, the additional section must remain
visible when the settings window is opened so an active filter is never hidden
from the user.

The exact choice and ordering of common versus additional rows may still be
adjusted later after real UI usage without changing filter semantics.

### Minimum And Maximum Semantics

For every numeric row:

```text
both empty:
    predicate is inactive

minimum only:
    value >= minimum

maximum only:
    value <= maximum

both:
    minimum <= value <= maximum
```

Minimum and maximum are inclusive, following backend semantics.

If both values are present:

- minimum must not exceed maximum

Invalid ranges prevent Apply.

### Unit Presentation

Each row uses one shared unit selector for both Minimum and Maximum.

The UI does not use separate units for the two bounds.

Byte-based rows use:

- B
- KiB
- MiB
- GiB
- TiB

Duration uses user-friendly labels:

- us
- ms
- s
- min
- h

Packet/count rows do not need a unit selector. They may show a static
`packets` / `count` label or an equivalent compact presentation.

The UI may display `min` even if the stable `.filter` text format uses a
different canonical token such as `m`.

### UI Units Are Presentation State

The unit selector is UI presentation state, not a new backend semantic field.

`AdvancedFlowFilterSpec` continues to receive normalized integer values.

Example:

```text
UI:
Original bytes
Minimum = 10
Unit = MiB
```

This maps to the existing absolute backend integer value.

The UI does not change `AdvancedFlowFilterSpec` to store display units.

### Exact Integer Representation

The UI preserves the current integer-only backend semantics.

When loading an existing filter value into the editor, the UI should choose a
convenient display unit only when the value can be represented exactly as an
integer in that unit.

Example:

```text
10485760 bytes -> 10 MiB
```

If no larger unit represents the value exactly:

```text
10485761 bytes -> 10485761 B
```

The UI must not introduce floating-point filtering semantics merely for display
purposes.

### Rule Count

Each populated bound remains one atomic predicate for the main-toolbar rule
count.

Examples:

- `packet_count.min` only = 1 rule
- `original_bytes.min + original_bytes.max` = 2 rules

A selected unit by itself with empty Minimum and Maximum does not create a
rule.

### Draft UX

Changing a unit selector must not create a filter predicate when both bounds
are empty.

Validation follows this RFC's existing non-aggressive draft-validation rules.

The UI must not calculate dynamic flow counts for arbitrary numeric ranges.

## Section Enabled State

Advanced Filter sections have a conceptual section-level Enabled checkbox.

Examples:

```text
Flow Protocol                             Enabled [x]

[x] TCP
[ ] UDP

[ + Exclusions ]
```

```text
Ports                                     Enabled [ ]

...configured port rules shown disabled/dimmed...
```

Purpose:

- users can temporarily disable part of a complex filter without deleting its
  configuration

The initial design uses Enabled at the section level.

The initial UI does not introduce per-rule Enabled controls.

Representative sections that may have Enabled state include:

- Address Family
- Flow Protocol
- Detected Protocol
- TLS Version
- QUIC Version
- Directionality
- Ports
- IP addresses
- Traffic
- Service
- Protocol Path
- Contains Layer

The exact visual placement may be polished later, but the state must remain
clear.

### Enabled Semantics

When a section is disabled:

- retain all configured rules in the filter document/UI draft
- visually dim or otherwise clearly mark the section as disabled
- omit that section's predicates from the effective filter passed to the
  evaluator

When re-enabled:

- restore the retained configuration without requiring re-entry

User-disabled state is different from capture-unavailable state.

Disabled:

- explicit user/document state
- may be shown dimmed

Unavailable in current capture:

- contextual warning
- rule remains logically enabled
- should use a distinct warning presentation rather than looking disabled

### Dirty State

Changing a section's Enabled state is a filter-document modification.

For a file-backed filter:

```text
Enabled [x] -> Enabled [ ]
```

marks the document dirty and the toolbar display may become:

```text
filter_name *
```

By contrast, if a Protocol Path becomes unavailable because another capture was
opened, that does not mark the document dirty.

Applicability state belongs to the current capture/session, not to the saved
filter.

### Rule Count With Disabled Sections

The main-toolbar `N rules` indicator counts only atomic predicates belonging
to enabled sections.

Example:

- Flow Protocol:
  - 2 configured predicates
  - Enabled
- Ports:
  - 3 configured predicates
  - Disabled
- Traffic:
  - 4 configured predicates
  - Enabled

Toolbar active rule count:

```text
6 rules
```

The 3 predicates stored in the disabled Ports section are not counted as
active rules.

A future tooltip may optionally expose configured-but-disabled rule counts,
but that is polish rather than an initial requirement.

### Persisting Disabled Configuration

Section Enabled state must eventually be persistable.

It is not acceptable for Save to discard the configured rules of a disabled
section.

The current development `.filter` format does not yet encode this
UI/document state.

This RFC records that gap as a format-evolution requirement.

This RFC does not modify the current grammar.

Before the first release containing Advanced Flow Filter, only the current
development format version needs to be readable.

Incompatible development-format bumps are allowed, and earlier unreleased
versions may become unsupported immediately.

A future format version, likely `format_version = 2`, may add section-enabled
state if needed.

Conceptually:

- while the current development format remains active, it has no persisted
  section Enabled state
- a future format revision can persist disabled sections without losing their
  configured rules

The exact future text grammar is deferred and must be designed separately
before implementation.

This RFC does not invent or lock in keys such as `port.enabled`.

### Effective Filter Model

The RFC records this conceptual separation:

```text
Saved/configured filter document
    +
section Enabled state
    ->
effective AdvancedFlowFilterSpec / effective evaluator input
```

and independently:

```text
Current capture Protocol Path data
    ->
transient applicability status
```

Applicability warnings do not mutate the configured document and do not
silently alter Enabled state.

The exact implementation structure/API can be designed later during the
document-state and backend-prerequisite passes.

## Validation UX

Validation should avoid aggressive error presentation while the user is still
in the middle of entering a new rule.

Agreed behavior:

- do not show disruptive errors while a newly added field is still empty and
  the user has not meaningfully edited it
- validation appears after meaningful editing or focus loss and always before
  Apply
- Apply must be disabled or rejected while the draft contains invalid rules

Examples of invalid draft states:

- port outside `0..65535`
- reversed port range
- invalid IP address
- invalid prefix
- empty service text rule

## Rule Count

The main-toolbar `N rules` indicator counts atomic active predicates, not the
number of categories.

Examples:

- `TCP` = 1
- `TLS` = 1
- `TLS 1.3` = 1
- `port 443` = 1
- `packet_count.min` = 1

The exact helper/API for this count can be finalized during implementation.

## Deferred UI Details

The following points remain intentionally open for future implementation
discussion:

- exact mapping/API between the three Protocol Path UI modes and the existing
  backend `exact_path` / `path_prefix` representation
- exact future `.filter` format evolution for persisted section Enabled state
- capture-level count-summary architecture
- exact implementation structure for document/configured spec versus effective
  enabled spec
- Qt implementation staging
- Tauri parity
- final styling and polish, including exact spacing, exact dialog wording, and
  any later reordering of common versus additional traffic rows

## Backend Prerequisite Notes

Most of the UI described here maps onto backend semantics already documented in
the backend RFC, but one explicitly noted prerequisite remains:

- Address family checkbox filtering needs a dedicated backend predicate before
  the full agreed UI can be implemented cleanly

This RFC does not propose changing any other backend contract in order to
describe the UI.

## Implementation Strategy

Implementation must be split into small coherent Codex passes rather than one
large end-to-end prompt.

Expected staged direction:

1. backend prerequisites
2. filter document/state model
3. main Flows-toolbar mode switching
4. settings-window shell plus checkbox groups
5. Ports editor
6. IP/CIDR editor
7. Traffic editor
8. Service editor
9. Protocol Path picker
10. Contains Layer editor
11. section Enabled state
12. Open / Save / dirty integration
13. format evolution and persistence
14. optional capture-level counts
15. Tauri parity
16. polish, tests, and docs

This RFC is intended to prevent future implementation prompts from restating
the entire UI design every time.

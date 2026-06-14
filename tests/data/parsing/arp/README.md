Synthetic ARP fixture captures for regression tests.

These `.pcap` files are tiny deterministic fixtures generated locally to cover:
- normal ARP request/reply handling;
- gratuitous ARP and ARP probe presentation;
- VLAN-tagged and padded Ethernet ARP frames;
- malformed, truncated, snaplen-truncated, and nonstandard ARP variants.

They are intentionally small and safe to keep in git as shared parser/presentation test data.

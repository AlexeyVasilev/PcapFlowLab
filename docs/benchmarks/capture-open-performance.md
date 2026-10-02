# Capture Open Performance Benchmark

## Benchmark identity

| Field | Value |
| --- | --- |
| Series | Capture Open Performance Benchmark |
| Run | #1 |
| Benchmark ID | `CAPOPEN-2026-10-03-01` |
| Date | 2026-10-03 |
| PFL version | 0.4.0 |

The short benchmark ID can be used in future performance notes and comparisons,
for example: "compared with `CAPOPEN-2026-10-03-01`".

This page records a small practical benchmark of **Pcap Flow Lab 0.4.0** against
**Wireshark 4.6.8**, together with PFL raw-capture and reusable-index measurements.

The benchmark is intentionally focused on a user-visible question:

> **How long does it take to open a capture and reach a usable analysis view?**

This is not a parser microbenchmark and it is not a claim that PFL and Wireshark
perform identical work while opening a capture. PFL is flow-oriented and defers a
significant amount of selected-flow, selected-packet, Stream, and deeper analysis
work until it is requested. Wireshark performs substantially richer packet
dissection for its packet-oriented view during initial loading.

The results therefore describe **time-to-usable-view on the tested system**, not
equivalent parser throughput.

## Benchmark system

| Component | Value |
| --- | --- |
| CPU | Intel Core i7-9750H @ 2.60 GHz |
| CPU topology | 6 physical cores / 12 logical processors |
| Physical RAM | 21,303,971,840 bytes (~19.84 GiB) |
| OS | Windows 11 Home, build 26200 |
| Capture drive | `D:` |
| Filesystem | NTFS |
| Storage device | NVMe SPCC M.2 PCIe SS |
| Storage size | 512,110,190,592 bytes (~476.94 GiB) |
| Windows-reported bus type | RAID |
| Page file | Enabled, 10,752 MB allocated |
| Pcap Flow Lab | 0.4.0, Qt release build |
| PFL commit | `66648455633473318417c124c2bfcfd156506618` |
| Wireshark / TShark | 4.6.8, 64-bit |

All capture files and PFL index files used in the benchmark were read from the
same local `D:` drive.

## Measurement method

The measurements were made as practical interactive application tests rather
than controlled microbenchmarks.

- The application was closed before each measurement.
- Most reported values are a single manual timed run. Some cases were repeated
  during testing and no large run-to-run variation was observed.
- The Windows filesystem cache was **not** explicitly flushed between runs.
- No Wireshark display filter was active.
- Wireshark used the **Default** configuration profile.
- In Wireshark name resolution settings, physical-address resolution was enabled;
  network-address and transport-address resolution were disabled.
- PFL raw-capture time was measured from initiating **Open** until the **Flow
  List** became available for use.
- PFL index-open time used the same endpoint: the Flow List becoming available.
- Wireshark time was measured from opening the capture until the packet list was
  fully displayed and usable.
- Memory was read from **Windows Task Manager -> Processes -> Memory** after the
  file had finished opening.
- The reported memory value is therefore **memory after open**, not peak memory.
- Wireshark was not measured on the largest captures once available system memory
  was already close to exhaustion on smaller cases.

The intent is to represent normal desktop usage on this machine, not cold-cache
storage throughput.

## Capture set

Exact file sizes below are filesystem sizes, not rounded values from the
Statistics UI.

| Capture | Container | Exact size (bytes) | Size (GiB) | Packets | Flows | Avg packet | Flows / 1M packets |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `BenignTraffic3.pcap` | PCAP | 853,841,091 | 0.795 | 1,311,897 | 25,304 | 635 B | 19,288 |
| `BenignTraffic.pcap` | PCAP | 2,048,000,100 | 1.907 | 3,664,164 | 116,550 | 543 B | 31,808 |
| `a_day1.pcap` | PCAPNG | 5,574,769,640 | 5.192 | 29,794,742 | 367,273 | 154 B | 12,327 |
| `BenignTraffic_0_1_2_3.pcap` | PCAP | 6,997,845,609 | 6.517 | 11,102,705 | 230,841 | 614 B | 20,791 |
| `s_day2.pcap` | PCAPNG | 11,937,655,812 | 11.118 | 54,198,023 | 89,350 | 187 B | 1,649 |
| `s_day1_s_day2.pcap` | PCAP | 21,105,187,152 | 19.656 | 101,526,610 | 266,011 | 192 B | 2,620 |
| `benchmark_composite_large.pcap` | PCAP | 46,326,806,920 | 43.145 | 169,657,051 | 1,195,710 | 257 B | 7,048 |

`a_day1.pcap` and `s_day2.pcap` retain their original `.pcap` filenames but are
PCAPNG containers.

The two larger PCAPs are derived captures created by sequential concatenation;
their timestamp ranges should not be interpreted as a natural continuous
capture.

## PFL raw-capture results

`GiB/s` below uses exact filesystem size divided by open time. `Mpps` means
**million packets per second** and is calculated as packet count divided by open
time.

| Capture | Container | Size (GiB) | Open time | Memory after open | Import GiB/s | Packet rate (Mpps) |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| `BenignTraffic3.pcap` | PCAP | 0.795 | 2.7 s | 224 MB | 0.295 | 0.486 |
| `BenignTraffic.pcap` | PCAP | 1.907 | 6.3 s | 437 MB | 0.303 | 0.582 |
| `a_day1.pcap` | PCAPNG | 5.192 | 77.1 s | 1,808 MB | 0.067 | 0.386 |
| `BenignTraffic_0_1_2_3.pcap` | PCAP | 6.517 | 18.2 s | 877 MB | 0.358 | 0.610 |
| `s_day2.pcap` | PCAPNG | 11.118 | 131.0 s | 2,566 MB | 0.085 | 0.414 |
| `s_day1_s_day2.pcap` | PCAP | 19.656 | 98.3 s | 4,776 MB | 0.200 | 1.033 |
| `benchmark_composite_large.pcap` | PCAP | 43.145 | 185.3 s | 8,605 MB | 0.233 | 0.916 |

The table shows why capture size alone is not a useful predictor of import cost.
Packet count, flow churn, packet-size distribution, protocol work, and container
format all matter.

## PFL vs Wireshark: raw capture open

Wireshark measurements were stopped after the 6.5 GiB case because available
system RAM was already nearly exhausted on this machine.

| Capture | Size (GiB) | PFL open | Wireshark open | Wireshark / PFL time | PFL memory | Wireshark memory | Wireshark / PFL memory |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `BenignTraffic3.pcap` | 0.795 | 2.7 s | 12.5 s | 4.63x | 224 MB | 1,748 MB | 7.80x |
| `BenignTraffic.pcap` | 1.907 | 6.3 s | 81.3 s | 12.90x | 437 MB | 4,361 MB | 9.98x |
| `a_day1.pcap` | 5.192 | 77.1 s | 224.3 s | 2.91x | 1,808 MB | 16,363 MB | 9.05x |
| `BenignTraffic_0_1_2_3.pcap` | 6.517 | 18.2 s | 194.6 s | 10.69x | 877 MB | 13,632 MB | 15.54x |
| `s_day2.pcap` | 11.118 | 131.0 s | Not measured | — | 2,566 MB | Not measured | — |
| `s_day1_s_day2.pcap` | 19.656 | 98.3 s | Not measured | — | 4,776 MB | Not measured | — |
| `benchmark_composite_large.pcap` | 43.145 | 185.3 s | Not measured | — | 8,605 MB | Not measured | — |

`Not measured` means that the comparison was intentionally stopped because of
the RAM limit of this benchmark machine. It is not a claim that Wireshark cannot
open those captures on other systems.

The `a_day1.pcap` Wireshark result in particular was recorded close to the
machine's physical-memory limit, so memory pressure and paging may influence its
elapsed time.

## PFL reusable index results

PFL indexes were measured only on the larger captures because index open on small
captures was too fast to time meaningfully by hand.

| Capture | Capture size | Index size | Index / capture | Raw open | Index open | Open speedup | Raw memory | Index memory | Memory reduction |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `s_day2.pcap` | 11.118 GiB | 1.961 GiB | 17.6% | 131.0 s | 1.8 s | 72.8x | 2,566 MB | 259 MB | 9.9x |
| `s_day1_s_day2.pcap` | 19.656 GiB | 3.704 GiB | 18.8% | 98.3 s | 4.5 s | 21.8x | 4,776 MB | 462 MB | 10.3x |
| `benchmark_composite_large.pcap` | 43.145 GiB | 6.311 GiB | 14.6% | 185.3 s | 13.3 s | 13.9x | 8,605 MB | 1,552 MB | 5.5x |

Exact index sizes:

| Index | Exact size (bytes) |
| --- | ---: |
| `s_day2_index.idx` | 2,106,045,670 |
| `s_day1_s_day_2_index.idx` | 3,977,412,082 |
| `benchmark_composite_large_index.idx` | 6,776,892,064 |

Index save time was measured for the largest composite:

- raw PCAP open: **185.3 s**
- save index after opening: **46.7 s**
- subsequent index open: **13.3 s**

For this workload, saving the index adds storage and one-time write cost, but a
single later reopen already saves substantially more time than the measured
index-save operation.

## Observations

### 1. Workload structure matters more than file size alone

`a_day1.pcap` is 5.192 GiB and contains 29.8 million packets and 367 thousand
flows, with an average captured packet size of **154 B**. It took PFL 77.1 s to
open.

`BenignTraffic_0_1_2_3.pcap` is larger at 6.517 GiB, but contains only
11.1 million packets and 231 thousand flows, with a much larger average captured
packet size of **614 B**. It opened in 18.2 s.

The resulting import rates differ substantially:

- `a_day1.pcap`: **0.067 GiB/s**, **0.386 Mpps**
- `BenignTraffic_0_1_2_3.pcap`: **0.358 GiB/s**, **0.610 Mpps**

This is why the benchmark reports both byte throughput and packet throughput.

### 2. Packet-heavy workloads can have modest GiB/s while still processing many packets

`s_day1_s_day2.pcap` contains 101.5 million packets with an average captured
packet size of 192 B. PFL opened it at approximately **1.03 Mpps**, even though
the byte-rate result is only **0.20 GiB/s**.

The 43.1 GiB composite has larger packets on average and reaches a higher byte
rate (**0.233 GiB/s**) while processing slightly fewer packets per second
(**0.916 Mpps**).

### 3. Classic PCAP was substantially faster than PCAPNG in these tested workloads

The current PFL implementation showed much higher import throughput on the
classic-PCAP cases than on the tested PCAPNG cases.

A particularly visible example is:

- `s_day2.pcap`: PCAPNG, 54.2M packets, 11.118 GiB, **131.0 s**
- `s_day1_s_day2.pcap`: classic PCAP, 101.5M packets, 19.656 GiB, **98.3 s**

The larger PCAP contains about 1.87x as many packets and is about 1.77x larger,
yet it opens faster in absolute time.

This is strong evidence that container/import-path overhead matters in the
current implementation, but it is **not** a controlled same-capture
PCAP-vs-PCAPNG A/B test. The result should therefore be treated as an observation
from this benchmark set rather than a general format-speed ratio.

### 4. Reusable indexes change the large-capture workflow

Across the three measured large captures, index open was approximately:

- **72.8x** faster for `s_day2`
- **21.8x** faster for `s_day1_s_day2`
- **13.9x** faster for the 43.1 GiB composite

Memory observed after opening the index was also approximately **5.5x-10.3x**
lower than after raw-capture import.

The index files occupied about **14.6%-18.8%** of the corresponding capture file
size.

For repeated analysis of large captures, the benchmark therefore shows a clear
trade-off: additional disk space and one-time index creation in exchange for much
faster subsequent startup and lower memory use after opening.

## Dataset provenance

### CICIoT2023

Source:

<https://www.unb.ca/cic/datasets/iotdataset-2023.html>

Used files include:

- `BenignTraffic.pcap`
- `BenignTraffic1.pcap`
- `BenignTraffic2.pcap`
- `BenignTraffic3.pcap`

`BenignTraffic_0_1_2_3.pcap` is a derived sequential merge of those four
captures.

### TU Wien smart-factory traffic

Source:

<https://researchdata.tuwien.ac.at/records/ghdc6-45k78>

Used files include:

- `a_day1.pcap`
- `a_day2.pcap`
- `s_day1.pcap`
- `s_day2.pcap`

The `a_day*` and `s_day*` captures contain smart-factory operational traffic
together with penetration-test attack traffic.

`s_day1_s_day2.pcap` is a derived sequential merge of `s_day1.pcap` and
`s_day2.pcap`.

### Agentic-PCAP

Source:

<https://huggingface.co/datasets/maureille/agentic-pcap>

The large composite includes:

- `data/pcaps/generated_high_background/benign/run1263.pcap`

## Derived-capture construction

`mergecap -a` was used so that packets are written in input-file order rather
than globally merged by timestamp. `-F pcap` writes the derived captures as
classic PCAP.

### CICIoT2023 merged benign capture

```powershell
& "C:\Program Files\Wireshark\mergecap.exe" `
  -a -F pcap `
  -w "BenignTraffic_0_1_2_3.pcap" `
  "BenignTraffic.pcap" `
  "BenignTraffic1.pcap" `
  "BenignTraffic2.pcap" `
  "BenignTraffic3.pcap"
```

### TU Wien 19.7 GB derived capture

```powershell
& "C:\Program Files\Wireshark\mergecap.exe" `
  -a -F pcap `
  -w "s_day1_s_day2.pcap" `
  "s_day1.pcap" `
  "s_day2.pcap"
```

### Large composite

```powershell
& "C:\Program Files\Wireshark\mergecap.exe" `
  -a -F pcap `
  -w "benchmark_composite_large.pcap" `
  "BenignTraffic_0_1_2_3.pcap" `
  "s_day1.pcap" `
  "s_day2.pcap" `
  "a_day1.pcap" `
  "a_day2.pcap" `
  "run1263.pcap"
```

Because these are sequentially concatenated benchmark corpora, capture-duration,
average-capture-rate, and timestamp-continuity statistics for the derived files
are not meaningful as real-world traffic-duration measurements.

## Limitations

This benchmark should be read with the following limitations in mind:

1. **Mostly single-run manual measurements.** The study is intended as a
   practical engineering check, not a statistically rigorous performance suite.
2. **Filesystem cache was not controlled.** Results represent normal interactive
   desktop usage rather than forced cold-cache storage tests.
3. **Memory is measured after open, not peak memory.** Values come from Windows
   Task Manager's `Processes -> Memory` column.
4. **PFL and Wireshark do not perform identical work while opening a capture.**
   PFL is flow-oriented and performs deeper selected-item analysis lazily;
   Wireshark builds a richer packet-oriented dissection view.
5. **Large Wireshark cases were not measured because of the RAM limit of the test
   machine.** This is a machine-specific measurement constraint, not a universal
   limitation of Wireshark.
6. **The PCAP-vs-PCAPNG observation is not a same-capture format A/B test.**
7. **Derived captures are synthetic sequential concatenations.** They are useful
   for scale testing but should not be interpreted as natural continuous capture
   sessions.
8. **This corpus does not strongly exercise deeply nested tunnel Protocol Paths.**
   It is primarily useful for capture-open scaling, packet density, flow churn,
   and repeated-analysis/index behavior.

## Interpretation

The most useful conclusion from these measurements is not a single
"PFL is N times faster" number.

The benchmark instead shows three practical characteristics of PFL 0.4.0 on this
machine:

- raw capture-open cost depends strongly on packet and flow structure, not only
  file size;
- the current classic-PCAP import path is substantially more efficient than the
  tested PCAPNG path;
- reusable PFL indexes can make repeated analysis of large captures dramatically
  faster while reducing memory observed immediately after opening.

These measurements are intended to document current behavior and provide a
repeatable baseline for future PFL performance work.

# Testing Log

Test methodology and results for features where "it compiled and the happy
path works" isn't sufficient evidence. Design rationale lives in
`IMPL_PLAN.md`; this file is the record of what was actually run and what
it proved. Organized by feature, newest entries at the top of each section.

---

## Jumbo Frames / MTU Control

Validated 2026-06-19 on the TRENDnet TUC-ET5G as `en9` for MTU control,
standard-MTU stability, max-configured-MTU stability, and jumbo ICMP traffic
first to a 9 KB-class peer limit, then to the full 16 KB-class hardware limit
with a peer that supports it.

### Methodology

- Built and installed a driver that reports max MTU `16334` through both the
  deprecated `GetMaxTransferUnit` path and the modern `getMaxTransferUnit`
  path.
- Raised driver log verbosity to level `3` so each MTU setter invocation and
  hardware write is visible.
- Used macOS `networksetup` to query the OS-visible valid MTU range for the
  Network Services hardware port.
- Used `ifconfig en9 mtu <value>` to exercise MTU transitions.
- Watched `log stream` for `applyMtuToHardware` output:
  - medium-mode jumbo bit state
  - RX bulk-in coalescing profile bytes
  - pause-watermark low/high bytes
- Confirmed the BSD-visible interface MTU using `ifconfig en9 | grep mtu`.

### Test 1 — OS-visible MTU range

Before jumbo support, macOS reported:

```text
networksetup -listvalidMTUrange 'TRENDnet USB 5G Adapter'
Valid MTU Range: 1280-1500
```

After implementing the MTU accessors, macOS reports:

```text
networksetup -listvalidMTUrange 'TRENDnet USB 5G Adapter'
Valid MTU Range: 1280-16334
```

This confirms the OS now sees the driver's advertised jumbo-capable maximum
transfer unit.

### Test 2 — MTU 9000

Command:

```sh
sudo ifconfig en9 mtu 9000
ifconfig en9 | grep mtu
```

Observed driver log:

```text
requested=9000 effective=9000
applyMtuToHardware: mtu=9000 MEDIUM_STATUS_MODE jumbo=1 val=0x0172 -> 0x0
applyMtuToHardware: mtu=9000 coalesce=07 00 01 1e ff -> 0x0
applyMtuToHardware: mtu=9000 pause_watermark=20 10 -> 0x0
```

Observed interface state:

```text
en9: ... mtu 9000
```

Expected and observed: jumbo enabled, standard high-speed coalescing profile
retained because `9000 <= 12500`, and pause watermark set to `0x1020`
(`20 10` on the wire).

### Test 3 — MTU 16334

Command:

```sh
sudo ifconfig en9 mtu 16334
```

Observed driver log:

```text
getMaxTransferUnit -> 16334
requested=16334 effective=16334
applyMtuToHardware: mtu=16334 MEDIUM_STATUS_MODE jumbo=1 val=0x0172 -> 0x0
applyMtuToHardware: mtu=16334 coalesce=07 00 01 18 ff -> 0x0
applyMtuToHardware: mtu=16334 pause_watermark=20 1a -> 0x0
```

Expected and observed: max MTU accepted, jumbo enabled, jumbo RX bulk-in
coalescing profile selected, and pause watermark set to `0x1a20`
(`20 1a` on the wire).

### Test 4 — Return to MTU 1500

Command:

```sh
sudo ifconfig en9 mtu 1500
```

Observed driver log:

```text
getMaxTransferUnit -> 16334
requested=1500 effective=1500
applyMtuToHardware: mtu=1500 MEDIUM_STATUS_MODE jumbo=0 val=0x0132 -> 0x0
applyMtuToHardware: mtu=1500 coalesce=07 00 01 1e ff -> 0x0
applyMtuToHardware: mtu=1500 pause_watermark=10 08 -> 0x0
```

Expected and observed: jumbo bit cleared, high-speed standard-MTU coalescing
profile restored, and pause watermark set to `0x0810` (`10 08` on the wire).

### Test 5 — jumbo ICMP traffic to peer limit

The peer supports jumbo frames up to roughly the 9 KB class, not the AQC111U
driver's full `16334` MTU ceiling. With both ends configured for the supported
path MTU, `tcpdump` on `en9` captured repeated jumbo ICMP request/reply pairs:

```text
sudo tcpdump -ni en9 icmp
00:56:03.153291 IP 169.254.50.50 > 169.254.124.250: ICMP echo request, id 18602, seq 53, length 9174
00:56:03.153501 IP 169.254.124.250 > 169.254.50.50: ICMP echo reply, id 18602, seq 53, length 9174
00:56:04.154878 IP 169.254.50.50 > 169.254.124.250: ICMP echo request, id 18602, seq 54, length 9174
00:56:04.155071 IP 169.254.124.250 > 169.254.50.50: ICMP echo reply, id 18602, seq 54, length 9174
00:56:05.157086 IP 169.254.50.50 > 169.254.124.250: ICMP echo request, id 18602, seq 55, length 9174
00:56:05.157281 IP 169.254.124.250 > 169.254.50.50: ICMP echo reply, id 18602, seq 55, length 9174
00:56:06.157845 IP 169.254.50.50 > 169.254.124.250: ICMP echo request, id 18602, seq 56, length 9174
00:56:06.158123 IP 169.254.124.250 > 169.254.50.50: ICMP echo reply, id 18602, seq 56, length 9174
00:56:07.158820 IP 169.254.50.50 > 169.254.124.250: ICMP echo request, id 18602, seq 57, length 9174
00:56:07.159096 IP 169.254.124.250 > 169.254.50.50: ICMP echo reply, id 18602, seq 57, length 9174
```

`tcpdump`'s displayed IPv4 length of `9174`, plus the 14-byte Ethernet
header, means the Ethernet frames are roughly `9188` bytes without FCS. That
is well beyond standard Ethernet's `1514` byte frame length, and the paired
request/reply traffic proves both jumbo RX and jumbo TX work at this size.

### Test 6 — streaming stability at MTU 1500 and MTU 16334

Regression soak with normal 4K video streaming after touching shared link-up,
RX buffer-pool sizing, TX staging-buffer sizing, and MTU hardware programming.

Results:

- MTU 1500: 4K streaming stable; no observed driver instability.
- MTU 16334: 4K streaming stable; no observed driver instability.

This validates ordinary traffic stability at both standard MTU and the
driver's maximum configured MTU. It does not by itself prove full-size 16 KB
jumbo frames on the wire because the streaming workload does not necessarily
emit maximum-sized packets.

### Test 7 — full 16 KB-class jumbo traffic

After adding peer hardware and a full L2 path that support 16 KB-class frames,
`tcpdump` on `en9` captured repeated near-ceiling ICMP request/reply pairs:

```text
tcpdump -ni en9 icmp
02:11:35.023015 IP 169.254.50.51 > 169.254.113.128: ICMP echo request, id 6277, seq 1, length 16314
02:11:35.023287 IP 169.254.113.128 > 169.254.50.51: ICMP echo reply, id 6277, seq 1, length 16314
02:11:36.024149 IP 169.254.50.51 > 169.254.113.128: ICMP echo request, id 6277, seq 2, length 16314
02:11:36.024385 IP 169.254.113.128 > 169.254.50.51: ICMP echo reply, id 6277, seq 2, length 16314
02:11:37.025391 IP 169.254.50.51 > 169.254.113.128: ICMP echo request, id 6277, seq 3, length 16314
02:11:37.025655 IP 169.254.113.128 > 169.254.50.51: ICMP echo reply, id 6277, seq 3, length 16314
02:11:38.026426 IP 169.254.50.51 > 169.254.113.128: ICMP echo request, id 6277, seq 4, length 16314
02:11:38.026692 IP 169.254.113.128 > 169.254.50.51: ICMP echo reply, id 6277, seq 4, length 16314
02:11:39.027234 IP 169.254.50.51 > 169.254.113.128: ICMP echo request, id 6277, seq 5, length 16314
02:11:39.027437 IP 169.254.113.128 > 169.254.50.51: ICMP echo reply, id 6277, seq 5, length 16314
```

`tcpdump`'s displayed IPv4 length of `16314`, plus the 14-byte Ethernet
header, gives roughly `16328` bytes without FCS. That is within the driver's
configured MTU ceiling (`16334`) and proves full 16 KB-class jumbo RX and TX
with matching peer hardware.

### Conclusion

MTU reporting and hardware programming are validated for `1500`, `9000`, and
`16334`. Jumbo traffic is validated both at the earlier 9 KB-class peer limit
and at the full 16 KB-class hardware limit with a capable peer. Ordinary 4K
streaming is stable at both MTU `1500` and configured MTU `16334`.

---

## TX Checksum Offload

Validated 2026-06-18 against the same remote Linux test host used for M6a,
using `ping -b en9` (binds the socket directly to the interface, bypassing
a stale ARP-cloned route that was sending test traffic out `en0` instead —
see "Reusable Methodology Notes").

### Methodology

Unlike RX, there's no per-packet TX descriptor checksum bit to verify
(confirmed against both Linux `aqc111_tx_fixup()` and the RE'd x86 TX
descriptor layout — neither has one). TX checksum offload is a pure
link-level register toggle (`SFR_TXCOE_CTL`), so the test is: does the OS
stop computing the checksum itself once we declare the capability, and
does hardware actually fill in a correct value afterward?

- Driver-side: the `txDrainOne` debug dump (`LogV`, extended from 16 to 64
  bytes this session specifically to reach the IP header checksum field)
  shows exactly what we hand to the USB pipe, before the chip touches it.
- `getTxChecksumInfo()` logged per packet (diagnostic only, not required
  for correctness — see `IMPL_PLAN.md`).
- **Local capture (`tcpdump`/Wireshark on `en9`, this machine) is not
  useful for proving hardware did the work** — it taps at the same point
  as our own driver-side dump (before the chip), confirmed by it showing
  the identical `0x0000` placeholder. Initial confusion mid-session about
  "why does Wireshark show a populated checksum outgoing" turned out to be
  inspecting the wrong packet (an RX reply, not the TX request) — see
  methodology notes below on correlating by IP ID before drawing
  conclusions from a capture.
- Remote-side capture/behavior is what actually proves hardware involvement,
  same principle as M6a's negative control: a standard Linux host's
  `ip_rcv()` validates the IP header checksum before any ICMP processing,
  so getting a reply is reasonably strong evidence of a valid checksum —
  **with one important caveat found this session, see Test 2.**

### Test 1 — TX checksum offload enabled

`getTxChecksumInfo` reports `flags=0x4` (`kIOUserNetworkPacketTxCsumIPHdr`
only — correct, since this traffic is ICMP and we only declared TX
hwassist for IP header + TCP + UDP, not ICMP, matching the x86 kext's
"skip ICMP, not worth it" precedent from M6a). Driver's outgoing buffer
shows IP header checksum `00 00` (OS recognized the declared capability
and stopped computing it itself — direct proof of "stack consumption",
the one thing M6a couldn't get without `dtrace`). Remote host received the
ping and replied normally.

### Test 2 — negative control, attempt 1 (invalid — sticky hardware register)

Temporarily commented out the `SFR_TXCOE_CTL` write in `hwOnLinkUp` and
rebuilt, expecting the checksum to stay at the invalid `0x0000` placeholder
and the remote to silently drop it (mirroring M6a's bad-checksum RX test).
Instead: checksum stayed `0x0000` as expected, **but the remote still
replied** — seemingly contradicting the "Linux validates checksums" logic
relied on for the RX negative control.

**Root cause: the SFR register is sticky.** `hwDisable()` never writes
`SFR_RXCOE_CTL`/`SFR_TXCOE_CTL` back to `0` — confirmed by reading the
code, no such write exists anywhere in the file. The AQC111U chip itself
never loses power across a dext Stop/Start cycle (only an actual USB
unplug/re-enumeration or an explicit write changes its registers), so the
hardware was still running with `0x67` left over from an earlier successful
test run, regardless of what the *current* build's code did. Skipping the
*enable* write doesn't disable anything if it was already enabled from
before — this is a real, generally-useful gotcha for testing any SFR
register on this hardware, not specific to checksum offload.

### Test 2 — negative control, attempt 2 (valid)

Physically unplugged and replugged the USB device — a genuine hardware
reset, not just a driver restart — with the `SFR_TXCOE_CTL` write still
disabled in code. Result: checksum stayed `0x0000`, and this time **the
remote correctly ignored it** (no reply). Re-enabled the write (reverted
the temporary change) to close the loop.

### Conclusion

Confirmed both directions with a real positive/negative pair, same rigor
as M6a: hardware enabled → OS leaves checksum blank, chip fills in a
correct value, remote responds. Hardware genuinely disabled (verified via
physical reset, not just a skipped write) → checksum stays invalid, remote
silently drops it. TX checksum offload is considered validated.

---

## M6a — RX Checksum Offload

Validated 2026-06-18 against a remote test host capable of sending
deterministic good- and bad-checksum TCP packets to a chosen target.

### Methodology

- Runtime log level raised to Debug (`tools/set-log-level.swift 2` or `3`)
  to see the per-packet `RX[n] frame[i] checksum: l3Type=... l3Err=...
  l4Type=... l4Err=... csumFlags=0x... readback=0x...` line on every RX
  packet (the one-shot-then-errors-only gate was removed during this
  session specifically because it was hiding the data needed for this
  testing — see commit history).
- `tcpdump -i en9` running concurrently with `log stream` so packets can be
  correlated between the wire and the driver by timestamp.
- A `nc -l <port>` listener on the test Mac, confirmed first with a
  known-good SYN (got a SYN-ACK back) before testing bad-checksum SYNs
  against the *same* listening port — this control step matters: a
  bad-checksum SYN to a **closed** port is indistinguishable from a
  closed-port RST/fast-reject and proves nothing either way.
- `netstat -s | grep "discarded for bad checksum"` was tried as a
  stack-side confirmation but **ruled out as unreliable for this purpose**:
  it stayed at `0` even for a confirmed-bad packet to a confirmed-open
  port. Given this session separately discovered that `ifconfig` capability
  flags are Skywalk-synthesized and disconnected from actual driver state,
  the working theory is this legacy BSD `tcpstat` counter likely isn't fed
  by the same ingestion path Skywalk-native (`IOUserNetworkEthernet`)
  netifs use — not evidence of a driver problem. Not pursued further;
  behavioral testing (below) is more direct anyway.

### Test 1 — clean packet

Hardware reports `l3Type=1 l3Err=0 l4Type=4 l4Err=0`. Driver result:
`csumFlags=0x700` (`IPChecked|IPValid|DataValid`), `readback=0x700`
(packet object persisted what was set). Good SYN to the test listener
got a SYN-ACK back, confirming the round-trip end to end.

### Test 2 — bad TCP checksum only (`l3Err=0, l4Err=1`)

Hardware reports `l4Err=1`. Driver result: `csumFlags=0x300`
(`IPChecked|IPValid` only — `DataValid` correctly withheld), `readback`
matches. Sent to the same listening port that just answered a good SYN
with a SYN-ACK: **no response of any kind** (no SYN-ACK, no RST) —
correlated by timestamp in tcpdump against the driver's `RX[...] l4Err=1`
log line for the identical packet. This is the proof that matters: same
target, same port, only the checksum varied, and the bad one was silently
dropped exactly as TCP behavior predicts for a corrupted segment —
independent of whatever internal counter does or doesn't track it.

### Test 3 — bad IP header checksum, good TCP checksum (`l3Err=1, l4Err=0`)

This test caught a real bug. Before fixing it, the driver checked L3 and
L4 error bits independently:

```cpp
if (l3Type == AQ_RX_PD_L3_IPV4 && !l3Err) { ... IPChecked|IPValid ... }
if ((l4Type == TCP || UDP) && !l4Err) { ... DataValid ... }   // no l3Err check
```

This matched the x86 kext's RE'd logic (also independent), but diverged
from the Linux driver's `aqc111_rx_checksum()`, which uses a combined
`if (L4_ERR || L3_ERR) return;` gate — *either* error disqualifies *both*
assertions. The reasoning: a corrupted IP header means the source/dest
addresses feeding the TCP/UDP pseudo-header checksum are unreliable, so
hardware's L4 check can't be trusted even if it reports clean — those
inputs could be corrupted in a way that still happens to checksum cleanly.

Fixed to match Linux's stricter behavior: `!l4Err && !l3Err` gates
`DataValid`. Confirmed after the fix: hardware reports `l3Err=1 l4Err=0`,
driver result is `csumFlags=0x0, readback=0x0` — both assertions
correctly withheld even though the hardware's L4 check alone reported
clean.

### Conclusion

All three checksum-state combinations relevant to TCP traffic (clean,
bad-L4-only, bad-L3-affecting-L4) verified end-to-end: wire → hardware
detection → driver flag computation → `IOUserNetworkPacket` persistence
(readback) → stack-level behavior. M6a is considered fully validated.

---

## Reusable Methodology Notes

- **To prove a packet was actually rejected, not just unlucky timing**:
  send a known-good control packet to the exact same target/port first,
  confirm it gets the expected response, *then* send the variant under
  test. Only a same-target, same-port, single-variable comparison is
  meaningful — testing against a closed port or a different target proves
  nothing.
- **`netstat -s` legacy counters and `ifconfig` capability flags are not
  trustworthy signals for `IOUserNetworkEthernet`/Skywalk-native
  interfaces.** Both have been empirically caught disagreeing with known-
  correct driver state this session (see `IMPL_PLAN.md` "Log Level
  Strategy" entry for the `ifconfig` case). Prefer direct protocol
  behavior (tcpdump/Wireshark) or the driver's own instrumented logging
  over these aggregate OS-level counters when verifying Skywalk-path
  driver behavior.
- **Correlate by timestamp, not by assumption.** `log stream` and
  `tcpdump` running concurrently, matched by sub-second timestamp, is
  what closes the gap between "the wire shows X" and "the driver did Y for
  that exact packet" — without that correlation, two separate true
  observations don't actually prove they're about the same packet. Same
  principle applies to correlating by IP ID / sequence number when
  comparing a local capture against a driver log line — confirm it's
  literally the same packet before concluding two observations disagree.
- **A local capture on the same machine that's transmitting is not
  reliable for proving hardware did something to a packet on the way out.**
  It taps at the same point the driver itself sees the buffer, before any
  hardware fixup — confirmed empirically during TX checksum offload
  testing. Capture on a third party (the remote end, a span port, or a
  separate machine) when the question is "what actually went out on the
  wire," not on the transmitting host itself.
- **SFR hardware registers on this chip are sticky across dext
  Stop/Start cycles.** The chip never loses power just because the driver
  process restarts, and nothing in this driver's `hwDisable()` resets
  `SFR_RXCOE_CTL`/`SFR_TXCOE_CTL` (or, likely, most other SFR registers) to
  a known state. If you're testing "what happens when register X is NOT
  set," skipping the write in code is not sufficient if it was set by an
  earlier test run — a register can stay enabled from a previous session
  even though the current build's code never wrote it. A genuine test
  requires a real hardware reset (physical USB unplug/replug), not just a
  driver restart. Caught this exact false negative during TX checksum
  offload negative-control testing.
- **A "standard" remote host's behavior is still not automatically
  trustworthy** — it can have its own offload/virtualization quirks (e.g.
  a VM's virtio-net path may skip real checksum verification as a
  performance optimization between hypervisor and guest). A positive
  result (the remote responded) is supporting evidence, not proof, unless
  corroborated by an independent check like Wireshark's own checksum
  validation on a capture taken at/near the remote, or by a working
  negative control proving the remote really does reject what it should.

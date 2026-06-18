# Testing Log

Test methodology and results for features where "it compiled and the happy
path works" isn't sufficient evidence. Design rationale lives in
`IMPL_PLAN.md`; this file is the record of what was actually run and what
it proved. Organized by feature, newest entries at the top of each section.

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

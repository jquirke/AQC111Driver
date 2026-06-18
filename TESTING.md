# Testing Log

Test methodology and results for features where "it compiled and the happy
path works" isn't sufficient evidence. Design rationale lives in
`IMPL_PLAN.md`; this file is the record of what was actually run and what
it proved. Organized by feature, newest entries at the top of each section.

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
  observations don't actually prove they're about the same packet.

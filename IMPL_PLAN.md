# AQC111 DriverKit Implementation Plan

## Architecture

Two DriverKit personalities in a single dext bundle:

**Personality A — AQC111** (`IOUserService`, matches `IOUSBHostDevice`)
- Forces Config 1 via `SetConfiguration(1, matchInterfaces: true)`
- Holds USB device session open for the lifetime of the driver to pin Config 1
- Calls `RegisterService()` to publish itself; triggers interface nub matching

**Personality B — AQC111NIC** (`IOUserNetworkEthernet`, matches `IOUSBHostInterface` bInterfaceClass=255)
- Receives the vendor interface as provider
- Uses `CopyDevice()` for control transfers (Personality A holds the exclusive device session)
- Opens bulk IN (EP2), bulk OUT (EP3), and interrupt (EP1) pipes
- Runs hardware init, registers Skywalk Ethernet interface, handles RX/TX/ITR async IO

### File Structure

```
AQC111/AQC111/
  AQC111.iig          Personality A: IOUserService
  AQC111.cpp          Personality A: Open device, SetConfiguration(1), RegisterService
  AQC111NIC.iig       Personality B: IOUserNetworkEthernet
  AQC111NIC.cpp       Personality B: init, RX/TX pipeline, interrupt handler, Skywalk
```

---

## Milestones

### M1 — Config 1 forced ✓

- Personality A matches device by VID/PID
- `SetConfiguration(1, true)` forces Config 1; interface nubs published
- Personality A holds session open; Config 1 stays selected

### M2 — HW init + MAC address + interface registered ✓

- `vendorRead` / `vendorWrite` wrappers (`bRequest=AQ_ACCESS_MAC`)
- MAC SFR init sequence (MEDIUM_STATUS_MODE, BM_INT_MASK, RX coalescing, BULK_OUT_CTRL, etc.)
- MAC address read from SFR_NODE_ID (6 bytes at `0x10`)
- Ethernet interface registered via `RegisterEthernetInterface`; visible as `en10`

### M3 — PHY bring-up + link status ✓

- Interrupt pipe (EP1) armed; 16-byte ItrData parsed on each completion
- Speed code → media word mapping; `reportLinkStatus` called
- PHY powered on via `AQ_PHY_OPS` (bRequest=0x61), FWPhyAccess 4-byte struct
- `ifconfig en10` shows `status: active, 1000baseT <full-duplex>`

### M4 — RX pipeline ✓

- Pool of 10 bulk IN URBs (EP2) pre-posted; re-armed on each completion
- Aggregate buffer parser: 4-byte header → pkt_count / desc_offset → per-packet 8-byte descriptors
- AQ_RX_HW_PAD (2 bytes) skipped; raw Ethernet frame delivered to Skywalk via `IOUserNetworkPacket`
- Frames visible in Wireshark and tcpdump

### M5 — TX pipeline ✓

- `TxPacketAvailable` fires via `IODataQueueDispatchSource::SetDataAvailableHandler`
- 8-byte LE descriptor prepended (bits 20:0 = frame_len) + raw Ethernet frame → EP3 bulk OUT
- `OnTxComplete` returns packet to `txcQueue`; drains next queued packet
- ARP resolves; `ping` succeeds

### M6 — DHCP + polish (pending)

Tasks:
- Fix media re-seat: cycle `SFR_RX_CTL` (stop → restart) in `hwOnLinkUp`, matching Linux behavior
- DHCP: `ipconfig set en10 DHCP` — acquire an IP address automatically
- RX checksum offload: enable `SFR_RXCOE_CTL`; decode L3/L4 result bits from RX descriptor (design below)
- TX checksum offload: enable `SFR_TXCOE_CTL`; advertise checksum capability to stack
- Multicast hash filter (`SFR_MULTI_FILTER_ARRY`) and promiscuous mode

**Pass signal:** DHCP address acquired; `iperf3` shows throughput in expected range for 1G/5G link.

#### M6a — RX checksum offload design

RX currently advertises no checksum offload, so macOS's TCP/IP stack recomputes IP/TCP/UDP checksums in software for every inbound packet. The AQC111U hardware already validates these checksums per packet and reports the result in the RX descriptor — this is read and forwarded, not invented from scratch. (A prior CPU-overhead measurement concluded the saving is too small to verify reliably on the project's current USB 2.0 test link — well under the noise floor of per-core profiling — so this is scoped as a correctness/plumbing change now, with the throughput payoff expected once tested at 1G+/5G.)

**Hardware bit layout** — cross-checked against three independent sources (x86 kext RE in `RE_LOG.md` "Checksum Offload" section, the Linux driver's `aqc111_rx_checksum()`/`aqc111.h`, and this driver's own existing descriptor parsing in `AQC111NIC.cpp`), all of which agree exactly:

RX Packet Descriptor `pd` (64-bit, already parsed for `drop`(bit31)/`ok`(bit11)/`pkt_len`(bits 30:16)) — checksum fields live in the lower 16 bits, disjoint from those:

| Bits | Field | Values |
|------|-------|--------|
| 0 | `L4_ERR` | 1 = L4 checksum error |
| 1 | `L3_ERR` | 1 = L3 (IP) checksum error |
| 4:2 | L4 type | `1`=UDP, `4`=TCP, else not checked |
| 6:5 | L3 type | `1`=IPv4, `2`=IPv6 |

Register `SFR_RXCOE_CTL` @ wValue `0x0034` must be written or the hardware won't populate those fields at all: `SFR_RXCOE_IP(0x01) | SFR_RXCOE_TCP(0x02) | SFR_RXCOE_UDP(0x04) | SFR_RXCOE_TCPV6(0x20) | SFR_RXCOE_UDPV6(0x40) = 0x67` — the same `0x67` mask the x86 kext used for its IOKit checksum capability. ICMP/IGMP intentionally excluded, matching the x86 kext's documented decision (negligible traffic, not worth the complexity).

**DriverKit API — three parts, not just "tell the OS and implement regardless":**

1. **Capability declaration** — `IOUserNetworkEthernet::getFeatureFlags()` (DriverKit NDK_22+, not currently overridden). Driver declares `kIOUserNetworkHWAssistRxChecksum` (`0x20000000`, `IOUserNetworkTypes.h`). Read once at `RegisterEthernetInterface`/attach time.
2. **OS→driver enable/disable** — `SetHardwareAssists`/`GetHardwareAssists`, already declared in `AQC111NIC.iig` and stubbed as no-ops in `AQC111NIC.cpp` (`SetHardwareAssists` logs and discards; `GetHardwareAssists` hardcodes 0). This is DriverKit's equivalent of BSD's `if_hwassist` enable mask / classic `ifconfig -rxcsum`/`+rxcsum`, conceptually Linux's `ndo_set_features`/`ethtool -K`. (The SDK marks these `__deprecated` in favor of lowercase `setHardwareAssists`/`getHardwareAssists`, but those replacements don't exist anywhere in this SDK's headers — the deprecated pair is the only concrete mechanism available.) The driver must store what the OS sets here and gate per-packet checksum reporting on it, rather than acting unconditionally.
3. **Per-packet result** — `IOUserNetworkPacket::setRxChecksumInfo(flags, value)`. Flags: `kIOUserNetworkPacketRxCsumIPChecked|IPValid` for a clean IPv4 header, `kIOUserNetworkPacketRxCsumDataValid` for a clean TCP/UDP checksum (`kIOUserNetworkPacketRxCsumPseudoHdr` not needed — that's for partial/running checksums, and this hardware does full pass/fail validation). `value` unused (0) — only meaningful for partial checksums.

**Safety principle** (matches Linux `aqc111_rx_checksum` exactly): only ever assert validity. On `L3_ERR`/`L4_ERR` or an unrecognized protocol, skip the call entirely so the existing software stack verifies the packet exactly as it does today — this makes the change pure upside with no new failure mode if the hardware misbehaves or a bit is misread.

**Implementation outline:**
- Add `hwAssistMask` ivar (`uint32_t`) — holds the OS's full enabled-features bitmask, not RX-checksum-specific (reusable for future TX checksum/TSO bits)
- Override `getFeatureFlags()` → `kIOUserNetworkHWAssistRxChecksum`
- Flesh out `SetHardwareAssists`/`GetHardwareAssists` to store/report `hwAssistMask`
- `hwOnLinkUp()`: write `SFR_RXCOE_CTL=0x67` unconditionally (hardware always validates; only the *forwarding* to the stack is gated)
- `OnRxComplete()`: extract the lower-16-bit checksum sub-fields from `pd`, call `setRxChecksumInfo` only when `hwAssistMask & kIOUserNetworkHWAssistRxChecksum` is set
- Log checksum sub-fields for the first few packets (reusing the existing one-shot dump pattern) plus unconditionally on any `L3_ERR`/`L4_ERR`

**Empirical finding (2026-06-18, confirmed via `log stream` from `Start()` onward):** `getFeatureFlags()` is called (multiple times, during attach/`RegisterEthernetInterface`) and `GetHardwareAssists` is called repeatedly right after it — but `SetHardwareAssists` is **never** called by the OS, not at attach and not observed otherwise. With `hwAssistMask` defaulting to `0`, `GetHardwareAssists` kept reporting "nothing enabled," which is almost certainly why `RXCSUM` never appeared in `ifconfig`. Conclusion: declaring a capability via `getFeatureFlags()` does not cause the OS to proactively enable it — the driver is expected to self-initialize `hwAssistMask` to match what it advertises (mirroring BSD's convention that `if_capenable` defaults to `if_capabilities` unless explicitly disabled), with `SetHardwareAssists` reserved for the OS to *change* that later (e.g. `ifconfig -rxcsum`). Fixed by setting `ivars->hwAssistMask = kIOUserNetworkHWAssistRxChecksum` in `init()` rather than leaving it `0`. Not yet independently verified against Apple documentation/source — flagged as worth a sanity-check, but acted on since it's directly supported by the observed call sequence.

**Correction (2026-06-18, later investigation): `ifconfig options=`/`hwassist=` is not usable evidence for this feature, in either direction.** Verified that `en9` already showed `TSO4,TSO6,PARTIAL_CSUM,ZEROINVERT_CSUM` (and `hwassist=` showed `CSUM_PARTIAL,CSUM_ZERO_INVERT,MULTIPAGES,TSO_V4,TSO_V6`) *before any hardware-assist code existed in this driver at all* — none of TSO, TX checksum, or `CSUM_PARTIAL` generation is implemented here. Skywalk synthesizes a default BSD-compatibility capability profile for `IOUserNetworkEthernet`-class netifs independent of what `getFeatureFlags()`/`GetHardwareAssists()` actually return. So the earlier reasoning ("RXCSUM should appear once `getFeatureFlags()` works") was wrong as a predictor regardless of whether the underlying DriverKit-level fix is correct — `ifconfig` simply isn't wired to those calls in an observable way. The `hwAssistMask` self-init fix is still believed correct (~90-95% confidence, based on the deprecation doc wording — `SetHardwareAssists`: "driver should implement this to update itself with requested assists," i.e. a mutation-request channel, not an init callback — and the observed call pattern: `GetHardwareAssists` queried repeatedly before any `SetHardwareAssists` call ever arrives, which only makes sense if the driver is expected to already hold a meaningful state). But this is no longer treated as confirmed via `ifconfig`; see revised verification below.

**Verification (functional, not performance — already established that's below the noise floor at USB 2.0):**
- `getFeatureFlags()`/`GetHardwareAssists()` are queried with the expected values — already confirmed via `log stream` (see empirical finding above)
- **Packet-path propagation (added instrumentation):** right after `pkt->setRxChecksumInfo(csumFlags, 0)` in `OnRxComplete`, call `pkt->getRxChecksumInfo(&flags, &value)` and log the round-trip. This is a direct getter/setter pair on the `IOUserNetworkPacket` object we created — immune to the Skywalk BSD-compat synthesis ambiguity that invalidated the `ifconfig` check — so it proves the packet object actually stored what we set, which `ifconfig` could never prove either way.
- Log-based wiring check during normal `ping`/`iperf3`: TCP/UDP packets should show `l4Err=0`, correct `l4Type`, non-zero `csumFlags` (already implemented)
- **Negative control (the important one):** send a deliberately corrupted-checksum packet from a peer (e.g. scapy with the checksum field manually clobbered after auto-computation) — confirm the driver logs `l4Err=1` and does *not* set `DataValid`. Proves hardware validation is real and wired correctly, not coincidentally always "valid"
- **Stack-consumption test (hardest item, optional/exploratory):** the only way to directly prove the stack *skips* its own software re-verification because of our flag (rather than just tolerating it being present) is a temporary, diagnostic-only build that asserts `DataValid` unconditionally regardless of `l3Err`/`l4Err`, paired with the same deliberately-corrupted peer packet — if the corrupted payload reaches the receiving socket unmolested, that proves consumption; if the OS still drops it, the flag isn't being trusted for validation-skipping the way assumed. Not done by default — this temporarily disables the safety principle above and must be reverted immediately after the experiment.
- Not pursuing: `dtrace -n 'fbt::in_cksum:entry'` call-count tracing — would directly prove software recompute is skipped, but Apple Silicon's `fbt` provider needs SIP relaxed, and this project has SIP intentionally re-enabled. Accepted limitation: full certainty on "did the stack actually skip its own checksum work" is not achievable with the current approach; the negative-control test plus optional stack-consumption test are the practical ceiling.

### M7 — Advanced hardware features (planned, post-stability)

- TSO (TX descriptor MSS field, bits 46:32)
- Jumbo frames (MTU > 1500; hardware supports ~16 KB)
- VLAN offload (RX descriptor bit 10; `SFR_VLAN_ID_CONTROL`)
- Wake-on-LAN

### M8 — PHY access polymorphism (planned, low priority)

The AQC111U firmware exposes two PHY control interfaces selected by `fw_ver_major`:

| `major` | Path | PHY commands |
|---------|------|-------------|
| `>= 0x80` | `FWPhyAccess` | `AQ_PHY_OPS` (bRequest=0x61), 4-byte struct |
| `< 0x80` | `DirectPhyAccess` | `AQ_PHY_POWER` (bRequest=0x31) + MDIO via bRequest=0x32 |

The x86 kext selects the path at `start()` time based on the raw major byte. The Linux driver does the same check in `bind()`.

**Current state:** The driver reads and logs `fw_ver_major` in `Start()` and warns if it is not `>= 0x80`, but all PHY code unconditionally uses the `FWPhyAccess` path. This is correct for the DUT (TRENDnet TUC-ET5G, firmware 130.5.32, `major=0x82`).

**Future work:** Gate all `hwEnable` / `hwDisable` PHY writes on `ivars->fwMajor >= 0x80`; implement the `DirectPhyAccess` path (bRequest=0x31 + MDIO) for older firmware devices. Until then the driver will start-fail gracefully (warning log) on `major < 0x80` hardware.

### Bug fix plan — RX stall recovery gaps (confirmed root cause, 2026-06-18, awaiting more occurrences before implementing)

**Symptom** (see README "Current bugs" #2): RX silently stops delivering frames mid-session; TX keeps working; recovery requires unplugging/re-enumerating the device. Recurred 3 times in one day (2026-06-18). Logs of all three occurrences saved at `notes/rx_stall_occurrence_{1,2,3}.log` for pattern comparison as more examples are collected.

**Root cause, confirmed via occurrence 3** (the first occurrence to capture actual error codes — occurrences 1 and 2 showed total silence with no error status at all, which is consistent with the same underlying issue manifesting slightly differently):

A `kIOReturnNotResponding` (`0xe00002ed`, `IOReturn.h:182`, "device not responding") event hits the device — cause TBD, possibly a transient bus/firmware hiccup. This leaves USB pipes stalled afterward (confirmed: `kUSBHostReturnPipeStalled` = `0xe0005000`, `IOUSBHostFamilyDefinitions.h:70`, appears as the synchronous return value of subsequent resubmission attempts). The driver has three independent gaps in stall recovery, one per pipe, and the actual occurrence-3 log hit all three within about 0.8 seconds:

1. **`OnRxComplete` (`AQC111NIC.cpp:1088-1098`):** `kUSBHostReturnPipeStalled` as a *completion status* is handled (`ClearStall()` + repost). Any other non-success completion status — including `NotResponding` — falls into an unconditional "terminal, do not repost" branch. The slot is abandoned forever, no recovery attempted.
2. **`OnItrComplete` (`AQC111NIC.cpp:1314`):** the "transient, fall through and repost" path calls `pipeItr->AsyncIO(...)` unconditionally but never checks its return value. When that resubmission itself synchronously returns `kUSBHostReturnPipeStalled` (observed in occurrence 3), it's logged but nothing acts on it — the ITR pipe now has zero outstanding transfers and can never complete again.
3. **`txDrainOne` (`AQC111NIC.cpp:1037-1044`):** on a failed resubmission, the packet is correctly bounced back to the completion queue with an error status, but `ClearStall()` is never called. The pipe stays stalled; only the next queued packet gets a chance to retry the same doomed call.

**Proposed fix (not yet implemented — gathering more occurrences first since this is a low-frequency, hard-to-reproduce-on-demand bug and the user is conserving session budget):**
1. In `OnRxComplete`, treat `kIOReturnNotResponding` the same as `kUSBHostReturnPipeStalled` on the completion path — `ClearStall()` + repost — rather than treating it as unconditionally terminal. (Other genuinely terminal statuses, e.g. device removal, should stay terminal; the fix is to widen the recoverable-status set, not remove the terminal path entirely.)
2. In `OnItrComplete`'s repost call and in `txDrainOne`'s resubmission, check the **return value of the `AsyncIO()` call itself**, not just completion status. If it's `kUSBHostReturnPipeStalled`, call `ClearStall()` on that pipe and retry the submission once before giving up.
3. General principle to apply everywhere a pipe's `AsyncIO()` is called for (re)submission: a `kUSBHostReturnPipeStalled` return value from the submission call is just as actionable as one arriving via a completion callback — both need `ClearStall()`. Today only the completion-callback path has this wired up, and only for RX/ITR, not TX.

**Why wait:** Only occurrence 3 has produced a concrete, decoded error trail; occurrences 1 and 2 showed no error status at all before the freeze, so it's not yet certain the same fix covers all observed patterns. Collecting more occurrences (saved the same way, `notes/rx_stall_occurrence_N.log`) before implementing, to confirm the fix addresses the actual recurring pattern rather than just the one well-captured instance.

---

## Known Risk Points

| Area | Risk | Mitigation |
|------|------|-----------|
| M6: RX CTL cycling | hwOnLinkUp must stop then restart RX precisely; wrong order = no RX | Mirror Linux `aqc111_rx_fixup` / link-up sequence exactly |
| M6: DHCP | Requires correct ARP handling (already working) + IP stack integration | Should work once static-IP ping is solid |
| General | Corpse budget (~2 unplug cycles/boot) exhausts quickly | Plan test runs to minimize unplugs; reboot to reset |

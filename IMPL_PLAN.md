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

**Status: validated 2026-06-18 against a real remote test host sending deterministic good/bad-checksum packets.** Full methodology and results in `TESTING.md` "M6a — RX Checksum Offload". Headline finding from that testing: the L3/L4 error-bit handling in "Implementation outline" above was under-specified — the original code checked `l3Err`/`l4Err` independently (matching the x86 kext's RE'd logic), but testing with a bad-IP-checksum/good-TCP-checksum packet (`l3Err=1, l4Err=0`) proved this was too permissive: a corrupted IP header means the addresses feeding the TCP pseudo-header checksum are unreliable, so the hardware's L4 check can't be trusted even when it reports clean. Fixed to gate `DataValid` on `!l4Err && !l3Err` (matching Linux `aqc111_rx_checksum`'s combined gate, not the x86 kext's independent one) — confirmed by retest to correctly withhold `DataValid` in that case.

#### M6b — TX checksum offload design

Unlike RX, confirmed against both Linux `aqc111_tx_fixup()` and the RE'd x86 TX descriptor layout that there is **no per-packet TX descriptor checksum bit at all** — TX checksum offload is a pure link-level register toggle. Write `SFR_TXCOE_CTL` (wValue `0x0035`, same `IP(0x01)|TCP(0x02)|UDP(0x04)|TCPv6(0x20)|UDPv6(0x40) = 0x67` bit layout as RX's `SFR_RXCOE_CTL`) once at link-up, and the hardware auto-detects and fixes up the checksum for every outgoing IP/TCP/UDP frame from then on, no per-packet driver involvement.

**Implementation:** `getFeatureFlags()` and `init()`'s `hwAssistMask` self-init both now use a shared `AQC111_HWASSIST_MASK` constant (RX bit plus `kIOUserNetworkHWAssistTxChecksumIPHdr|TCP|UDP`) so the two can't drift apart. `hwOnLinkUp()` writes `SFR_TXCOE_CTL` alongside the existing RX write. `txDrainOne()` logs `getTxChecksumInfo()` diagnostically (not required for correctness, since hardware auto-detects headers itself) — mirrors the RX readback pattern for verification visibility.

**Status: validated 2026-06-18.** Full methodology and results in `TESTING.md` "TX Checksum Offload". Headline finding: confirmed `getTxChecksumInfo` reports `flags=0x4` (`IPHdr` only, correct for ICMP traffic since ICMP isn't declared), and that the OS genuinely stops computing the IP header checksum itself once the capability is declared (direct proof of "stack consumption" — the thing M6a couldn't get without `dtrace`). Negative-control testing surfaced an important hardware quirk: `SFR_TXCOE_CTL`/`SFR_RXCOE_CTL` are **sticky across dext Stop/Start cycles** (the chip never loses power on a driver restart, and `hwDisable()` doesn't reset these registers) — a first attempt at disabling TX offload by skipping the write got a false negative because the register was still enabled from an earlier test run. A genuine negative control required a physical USB unplug/replug to force a real hardware reset. See `TESTING.md` "Reusable Methodology Notes" for the general lesson.

#### M6c — Jumbo frame / MTU control design

MTU was previously hardcoded to 1500: `SetMTU()` was a no-op stub, `GetMaxTransferUnit()` hardcoded `*mtu = 1500`, and `txDrainOne()` hard-rejected anything over 1514 bytes. The AQC111U supports jumbo frames up to ~16KB.

**Hardware** — cross-checked against two independent sources that agree exactly on the watermark tiers: Linux's `aqc111_change_mtu()`/`aqc111_configure_rx()` (`notes/aqc111.c`) and the x86 kext RE (`RE_LOG.md`, now updated with the confirmed `SFR_PAUSE_WATERLVL_LOW`/`_HIGH` register address `0x0054`/`0x0055`). Three registers are MTU-aware: `SFR_MEDIUM_STATUS_MODE` bit 6 (jumbo enable, set when `mtu > 1500`), `SFR_PAUSE_WATERLVL_LOW` (new, tiered `0x0810/0x1020/0x1420/0x1A20` by MTU bucket), and the existing `SFR_RX_BULKIN_QCTRL` coalescing register (gets a dedicated jumbo profile `07 00 01 18 ff` when `mtu > 12500`, overriding the speed-based profile).

**DriverKit API**: both the deprecated dispatched pair (`SetMTU`/`GetMaxTransferUnit`) and the modern `LOCALONLY` pair (`setMaxTransferUnit`/`getMaxTransferUnit`, `NDK_21`) are implemented, sharing a `setCurrentMtu()`/`applyMtuToHardware()` helper pair. `getMaxTransferUnit()`/`GetMaxTransferUnit()` report the hardware ceiling (`16334`) unconditionally rather than the currently-configured MTU — confirmed correct via `networksetup -listvalidMTURange`, which uses this as a capability/range query (the OS tracks the actually-configured MTU itself; the driver's job is to enforce and apply it in hardware, not to be the source of truth for "what's set now").

**Implementation also fixed a gap not in the original plan**: the `IOUserNetworkPacketBufferPool`'s `bufferSize` was hardcoded to `2048` — far too small for a jumbo frame copy in `OnRxComplete`. Resized to `AQC111_MAX_FRAME_LEN` alongside the TX staging buffer (`AQC111_TX_BUF_SIZE`). RX/TX frame lengths are now gated against `ivars->currentMtu + 14` instead of the old hardcoded `1514`.

**Status: validated 2026-06-19/20** for MTU `1500`/`9000`/`16334` hardware programming and the OS-visible `1280-16334` valid-MTU-range, plus jumbo ICMP traffic first up to the original test peer's ~9KB-class limit and then to the full 16KB-class hardware limit with matching peer hardware (`tcpdump` IPv4 length `16314`, about `16328` bytes at Ethernet without FCS). 4K-streaming stability soaks also passed at both MTU `1500` and configured MTU `16334`. Full methodology in `TESTING.md` "Jumbo Frames / MTU Control".

### M6d — Endianness cleanup

Replaced raw pointer-cast reads/writes of multi-byte device payloads (e.g. `*(const uint64_t *)(buf + ...)`) — host-endian-fragile and technically unaligned-access UB even though harmless on Apple Silicon today — with explicit `readLe16/32/64`/`writeLe16/32/64` helpers and typed `aqRead16`/`aqWrite16`/`aqVendorOut32` wrappers. Applied to RX aggregate-header parsing, RX packet descriptor parsing, TX descriptor construction, and all 16-bit SFR/32-bit PHY-firmware register access. Wire bytes unchanged on Apple Silicon (verification: signing-disabled build passes); the value is portability and removing UB, not a behavior change.

### M6e — 802.1Q VLAN support design (Layer 1 software VLAN validated; hardware tag offload blocked, confirmed via Apple DTS)

Two genuinely separate DriverKit mechanisms, researched before planning (including a second model's independent read on a public-docs ambiguity — see `RE_LOG.md` "Open Items" for the related kext RE side-investigation):

1. **Software VLAN accommodation** (`kIOUserNetworkHWAssistSoftwareVlan` / `IOUserNetworkEthernet::SetSoftwareVlanSupport(bool)`) — maps to BSD's `IFNET_VLAN_MTU`: the driver promises to tolerate frames 4 bytes longer than the configured MTU so the OS's `vlan(4)` pseudo-interface layer can add/remove tags entirely in software, above the driver. Well-documented, low-risk, same capability-declaration pattern as checksum/MTU.
2. **True hardware tag insert/strip** (`IOUserNetworkPacket::getVlanTag()`/`setVlanTag()`, `NDK_24`) — the AQC111U genuinely supports this in silicon: RX descriptor bit 10 (tag present) + tag in bits 63:32 (shift `0x20`); TX descriptor bit 29 (insert tag) + tag in bits 63:48 (shift `0x30`) — confirmed via `RE_LOG.md`, matches Linux's `aqc111_rx_fixup`'s `__vlan_hwaccel_put_tag`/`aqc111_tx_fixup`'s `vlan_get_tag`. The capability gate the SDK docs reference (`kFeatureHardwareVlan`) **does not exist as a public constant anywhere in this SDK** — confirmed by grepping the entire `NetworkingDriverKit.framework/Headers/` tree and reading the full `hwAssist` enum in `IOUserNetworkTypes.h` line by line. Now confirmed via Apple DTS to be a genuine, permanent gap rather than something to chase empirically — see below.

**Existing fact found during research, later fixed**: `hwOnLinkUp()` already wrote `SFR_VLAN_ID_CONTROL` (`0x002B`) `= 0x10` (`SFR_VLAN_CONTROL_VSO`, "VLAN Stripping On") — inherited unmodified from the original x86 kext RE'd link-up sequence. That was wrong for the layer-1 software VLAN path: it stripped inline 802.1Q headers before macOS `vlan(4)` could demux them, while this driver does not yet deliver RX descriptor VLAN metadata to Skywalk. The layer-1 fix writes `0x00` instead, keeping tags inline.

**Out of scope for this pass**: hardware VLAN ID *filtering* (`SFR_VLAN_ID_ADDRESS`/`SFR_VLAN_ID_DATA0`, Linux's `aqc111_vlan_rx_add_vid`/`kill_vid`, `NETIF_F_HW_VLAN_CTAG_FILTER`) — a separate, optional performance feature (hardware-side allow-list of VLAN IDs); software-side VLAN demuxing works fine without it.

**Concrete bug to fix regardless of which layer is used**: `txDrainOne()`'s size check and `OnRxComplete()`'s upper-bound check both gate on `ivars->currentMtu + AQC111_ETH_HEADER_LEN` (14) with no allowance for a VLAN tag — a software-tagged frame at MTU 1500 is 1518 bytes and would be rejected as "too large" by both checks today.

**Step 0 result (2026-06-20): baseline tested, confirmed broken.** Built a deterministic, scripted test harness (`tools/baseline-vlan0.sh`) and first established a known-good *reference* using Apple's CDC/ECM fallback driver (not DriverKit) — `vlan0` on tag `1234` produced remote-visible `802.1Q` ICMP, 0% packet loss, proving the adapter, peer, VLAN ID, route, and scoped-ARP test method are all valid. Re-ran the identical setup against the unmodified DriverKit driver: local `tcpdump` on `en9` decodes the outbound frame as correctly VLAN-tagged (`802.1Q`, tag `1234`), but **the remote end receives nothing at all**. Switching back to CDC with the same setup immediately works again. Conclusion: this rules out a test-harness problem and confirms a real bug specific to the DriverKit TX path when handling VLAN-tagged (4-byte-larger) frames — not merely "hardware offload isn't implemented yet," software accommodation is actively broken. (Separately noted: the local capture's IP header checksum reads `0000` at this point, which is expected/correct TX-checksum-offload placeholder behavior per M6b, not evidence of a second bug.) Full write-up in `notes/cdc-vlan-baseline-2026-06-20.md`; raw logs in `notes/{baseline,diag,setup}-vlan0.log`.

**Step 1 result (2026-06-20): Layer 1 software VLAN support validated.** `SetSoftwareVlanSupport(true)` (note: a concrete base-class method the driver *calls*, not an `override` — the plan above had this backwards) called in `Start()`, `kIOUserNetworkHWAssistSoftwareVlan` added to the hwAssist mask, `AQC111_VLAN_TAG_LEN` (4) added to the TX/RX size checks and buffer sizing, and hardware VLAN stripping disabled by writing `SFR_VLAN_ID_CONTROL=0x00` on link-up. Confirmed via multiple independent signals: MTU correction `1496→1500`; inline tag present in the driver's TX buffer; remote-side wire capture; then a clean `/24` rig (`172.16.123.20/24` local `vlan0`, `172.16.123.10/24` remote, tag `1234`) proving full bidirectional ICMP. Parent `en9` capture showed both directions as `802.1Q vlan 1234`; `vlan0` capture showed both directions decapsulated as IPv4. A mismatched-VLAN negative control with remote tag `1235` showed frames visible on parent `en9` but absent from local `vlan0`, proving software demux by VLAN ID works and the driver is preserving tags rather than flattening all tagged traffic. Full detail in `TESTING.md` "VLAN Support". (Update 2026-07-02: the `SetSoftwareVlanSupport(true)` call was subsequently removed from `Start()` (`aee26cf`) after an A/B/A bench test confirmed it has no observable effect in any direction — the `kIOUserNetworkHWAssistSoftwareVlan` mask bit alone provides the VLAN-MTU accounting, and the full Step 1 validation passes identically without the call; see `TESTING.md` "VLAN Support" Step 2.)

**Verification**: same rigor as RX/TX checksum offload — parent/remote capture vantage points, not just the transmitting Mac. Positive test complete: real `802.1Q vlan 1234` tags visible on parent, `vlan0` decapsulates both request and reply, ICMP succeeds. Negative test complete: remote sends `vlan 1235`, parent sees the tagged frame, local `vlan0` for tag `1234` does not. Results in `TESTING.md` "VLAN Support".

**Layer 2 (hardware tag insert/strip): definitively blocked, confirmed via Apple DTS (2026-06-23), not just empirically untested.** Full correspondence/notes in `notes/vlan_re.md` (local working notes, not tracked in git — same as `notes/aqc111.c`). Filed with Apple DTS and confirmed: `kFeatureHardwareVlan` missing from the public `NetworkingDriverKit` headers is a genuine SDK/documentation gap worth filing, not user error; hardware VLAN tag insert/strip through `getVlanTag()`/`setVlanTag()` is not believed reachable from a third-party DriverKit USB Ethernet driver on any current public surface; there is no entitlement, private NDK version, or other documented/secret switch that enables it. Per DTS directly: `getHardwareAssists()`/`setHardwareAssists()` were never set up to pass through arbitrary bit values outside the published `kIOUserNetworkHWAssist*` enum — even knowing the unpublished constant's value wouldn't let a third-party driver actually set it, since the accessors strip anything not in that defined set.

Cross-checked against the legacy IOKit world the same day (`RE_LOG.md` "getFeatures() — legacy IOKit VLAN advertisement"): the x86 kext's `getFeatures()` returns `0x12` = `kIONetworkFeatureHardwareVlan (0x2) | kIONetworkFeatureTSOIPv4 (0x10)` — a real, working, documented IOKit capability bit. Hardware VLAN capability advertisement had a legitimate mechanism in the legacy IOKit world; DriverKit's lack of a published equivalent looks like a gap in the new SDK, not evidence the underlying concept is somehow unsupportable.

**Empirical confirmation (2026-07-02, branch `test-hardware-vlan-bit`): DTS's verdict tested directly, at DTS's own suggestion.** Declared the undocumented BSD/KPI value `IF_HWASSIST_VLAN_TAGGING` (`0x00010000`, numerically adjacent to the published SoftwareVlan bit `0x00020000`) via `getFeatureFlags()` + hwAssist self-init, with live tagged bench traffic, in two permutations: alongside the SoftwareVlan bit, and alone. Result: ignored wholesale. `getVlanTag()` never returns true, tags stay inline both directions, and — decisively — with the bit alone the `vlan(4)` child clamps to MTU 1496, i.e. the unpublished value doesn't even receive the VLAN-MTU accounting the published bit gets. One refinement to DTS's "the accessors strip anything not in the defined set": nothing is observably stripped *in a setter*, because the OS never calls either generation of `setHardwareAssists` (deprecated NDK_21 `SetHardwareAssists` or the mask-based NDK_22 `setHardwareAssists`, both implemented with logging for this test) in any configuration — whatever consumes the declared flags simply disregards unknown bits. Full run detail in `TESTING.md` "VLAN Support" Step 2; the experiment branch is kept unmerged for reference.

Feedback filed (2026-07-03): `FB23530504` — the SDK/documentation bug (`getVlanTag()`/`setVlanTag()` doc comments in `IOUserNetworkPacket.iig` reference `kFeatureHardwareVlan`, which is defined nowhere in the public SDK; DTS confirmed a genuine bug and requested the FB number). A companion Suggestion requesting a public hardware VLAN capability (framed as an IOKit→DriverKit capability regression: the vendor's legacy kext advertised `kIONetworkFeatureHardwareVlan` for this same silicon) is drafted in `notes/fb2_hardware_vlan_er.md`, filing pending.

Conclusion unchanged in practice, now on empirical rather than just DTS-asserted footing: Layer 1 (software VLAN) remains the only supported path. Layer 2 is not worth picking back up unless Apple responds to the Feedback reports with something new.

### M6f — Forced media selection (implemented and validated 2026-06-23)

The actual OS-facing media-selection entry point is `handleChosenMedia(MediaWord chosenMedia)` (`LOCALONLY NDK_21`), not `SelectMediaType` — the latter is explicitly `@deprecated, use handleChosenMedia instead` per `IOUserNetworkEthernet.iig`. Previously `handleChosenMedia` logged and returned `kIOReturnSuccess` with no hardware effect: PHY init always advertised all four rates regardless of what was requested, so `ifconfig en9 media 100baseTX` was accepted but silently had no effect on the wire.

**Implementation:** `handleChosenMedia` masks `chosenMedia` against `kIOUserNetworkMediaEthernetMask`, rejects `kIOUserNetworkMediaOptionHalfDuplex` (this hardware has no forced-half-duplex mode at any rate, matching Linux's explicit `DUPLEX_FULL`-only check in `aqc111_set_link_ksettings`), and maps the base type to a single `AQ_ADV_*` bit (auto/none/manual → full `0xF`, otherwise exactly one bit — 100M/1G/2.5G/5G). The chosen mask is stored in a new ivar, `ivars->phyAdvertiseMask` (previously a `hwEnable`-local literal), specifically so a forced selection survives a later `ifconfig down`/`up` cycle rather than silently reverting to full autoneg on the next `hwEnable` — the same class of bug already flagged for M6g/M6h's filter bits. The actual `AQ_PHY_OPS` write was extracted into a shared `applyPhyAdvertise()` helper used by both `hwEnable` (bring-up) and `handleChosenMedia` (live runtime change), so the two paths can't drift apart. If the interface is already up, the new mask is applied immediately; otherwise it takes effect on the next `hwEnable`.

Note this hardware (and this chip's Linux driver) has no genuine forced/non-autoneg PHY mode at any rate — "forcing" a rate here means restricting the autoneg advertisement to one bit, not disabling negotiation. This matters for interop: forcing a *link partner* to genuinely disable autoneg (e.g. `ethtool -s <if> speed 100 duplex full autoneg off`) while this driver stays on full autoneg can fail to link at all (IEEE 802.3 parallel detection can sense speed but not duplex, and many PHYs — including this one's link partner in testing — just don't establish a stable link against a hard-forced peer). Restricting the link partner's *advertisement* while leaving its autoneg on (`ethtool -s <if> speed 100 duplex full autoneg on`, or `advertise <mask>`) is the symmetric, well-supported case and is what should be used when testing interop against this driver.

**Validated end-to-end** (full trail in `TESTING.md` "Media Selection"): baseline autoneg regression confirmed across three real peers (1G/2.5G/5G-capable), correctly following remote-side advertisement changes including a live mid-session renegotiation. Forcing 100baseTX and 2500base-T (note: macOS `ifconfig`'s media-name table wants the hyphenated `2500base-T`, not `2500baseT`) both confirmed via this driver's own log/`ifconfig` *and*, for the 2500 case, independently via the remote's `ethtool` seeing our restricted advertisement. Confirmed the forced selection survives an `ifconfig down`/`up` cycle (the specific bug class `phyAdvertiseMask` was added to avoid) rather than reverting to full autoneg. Reverting to `media autoselect` correctly climbs back to the link's actual max each time. The half-duplex rejection path is implemented but not yet exercised on real hardware.

### M6g — Promiscuous mode (implemented and validated 2026-06-23)

`SetPromiscuousModeEnable` previously logged and returned `kIOReturnSuccess` with no hardware effect. `hwOnLinkUp`/`hwOnLinkDown`/`hwDisable` hardcoded `SFR_RX_CTL` (`0x000B`) to a fixed `0x0288` (`IPE|START|AB`) on every link transition, with no ivar tracking current filter mode.

Linux's `aqc111_set_rx_mode` (`notes/aqc111.c:529`) is the reference implementation: `SFR_RX_CTL_PRO` (`0x0001`) is the promiscuous bit.

**Implementation:** added `ivars->rxFilterBits` (holds RX_CTL filter bits distinct from the fixed `IPE|START|AB` base) and a shared `doSetPromiscuousMode()` helper that ORs/ANDs `SFR_RX_CTL_PRO` into it and, if the interface is already up, applies it live. `hwOnLinkUp` now ORs in `ivars->rxFilterBits` instead of hardcoding `0x0288`, so the setting survives an `ifconfig down`/`up` cycle. Also implemented the modern lowercase `setPromiscuousModeEnable` (`LOCALONLY`) alongside the deprecated capital form, both calling the same helper — confirmed empirically (via Wireshark triggering it) that the deprecated capital form is what Skywalk actually calls on this NDK, but both are wired per the consistency policy in "Known Risk Points" below, in case a future release switches which one fires.

**Validated end-to-end** (full trail in `TESTING.md` "Promiscuous Mode"): negative control confirmed broken beforehand — a frame addressed to a foreign (non-matching, non-broadcast/multicast) destination MAC was silently dropped before ever reaching `OnRxComplete`, confirmed at both the driver-log level and via `tcpdump` on a direct point-to-point link (no switch in the path, so every frame the remote sends already reaches this NIC's PHY regardless of destination MAC — the only question was whether this driver's own hardware filter dropped it). After implementation: enabling promiscuous mode wrote `RX_CTL=0x0289` (`SFR_RX_CTL_PRO` set) and the same foreign-MAC frame became visible in `tcpdump`; disabling it again (confirmed via `tcpdump --no-promiscuous-mode`, to rule out `tcpdump` itself re-triggering promiscuous mode and contaminating the negative half of the test) reverted to `RX_CTL=0x0288` and the frame disappeared again.

### M6h — Multicast filtering (implemented and validated 2026-06-23)

`SetAllMulticastModeEnable` and `SetMulticastAddresses` previously logged and returned `kIOReturnSuccess` with no hardware effect. Same underlying gap as M6g: no ivar tracked current filter state for `SFR_RX_CTL`.

Linux's `aqc111_set_rx_mode` (`notes/aqc111.c:529`) is the reference implementation: `SFR_RX_CTL_AMALL` (`0x0002`) is accept-all-multicast; `SFR_RX_CTL_AM` (`0x0010`) plus a hash written to `SFR_MULTI_FILTER_ARRY` (`0x16`) is per-address multicast filtering, using the standard 64-bucket CRC32-hash scheme (`ether_crc(mac) >> 26`, i.e. `bitrev32(crc32_le(~0, mac, 6)) >> 26`) indexing an 8-byte table.

**Implementation:** extends the same `ivars->rxFilterBits`/`applyRxFilterBits()` machinery from M6g. `doSetAllMulticastMode()` toggles `SFR_RX_CTL_AMALL`. `doSetMulticastAddresses()` ports the CRC32/bitrev32 hash algorithm faithfully (verified against a from-scratch Python reference before coding, not just transcribed from memory), computes and logs each address's hash bit (byte/bit breakdown) for runtime visibility, writes the 8-byte table to `SFR_MULTI_FILTER_ARRY`, and toggles `SFR_RX_CTL_AM` based on `count > 0`. Also mirrors Linux's `mc_count > AQ_MAX_MCAST` mutual-exclusion behavior exactly (`AQ_MAX_MCAST_ADDRESSES = 64`, matching Linux's `AQ_MAX_MCAST`): when the OS hands over more groups than the 64-bucket table can represent precisely, falls back to `AMALL` *instead of* writing a partial table — there's no value in a table AMALL already supersedes. That fallback is sticky until an explicit `SetAllMulticastModeEnable(false)`, not auto-cleared just because count later drops back under the threshold, to avoid fighting with that independently-driven call. Both deprecated-capital and modern-lowercase forms implemented for both methods, per the M6g consistency policy.

**Validated end-to-end** (full trail in `TESTING.md` "Multicast Filtering"): negative control confirmed broken beforehand on a direct point-to-point link (no switch needed — same methodology as M6g). After implementation: a real IP multicast group join correctly computed and added the right hash bit (verified against an independent Python port of the algorithm computed *before* implementing, then confirmed bit-for-bit against the live filter table dump), and delivered all the way to a real listening UDP socket — not just visible in `tcpdump`. A second, deliberately non-colliding address confirmed still dropped (proving the filter discriminates by hash bit, not just "any multicast passes"). The `AQ_MAX_MCAST_ADDRESSES` fallback was validated by temporarily lowering it to 5 in a real build, confirmed sticky (the OS's own ~7-8 standing multicast joins exceed it at attach time), and confirmed the same previously-dropped non-colliding address became admitted once `AMALL` engaged — proving the fallback genuinely bypasses per-address filtering rather than coincidentally matching the table. Restored to `64` after validating.

The reverse direction (count dropping back under the threshold) initially surfaced a real bug — the fallback couldn't retract once triggered — now fixed; see "Bug fix plan — AMALL fallback can never be retracted once triggered by address-count overflow" below for the full fix and validation.

### M6i — `hwAssistMask` not enforced for TX checksum / VLAN (flagged, not yet scoped)

`SetHardwareAssists`/`GetHardwareAssists` (`AQC111NIC.cpp:1804-1812`) store/report `ivars->hwAssistMask`, and RX checksum correctly gates delivery on it (`OnRxComplete`, ~line 1628). TX checksum and inline-VLAN-tag preservation do not consult the mask at all — they happen unconditionally regardless of what the OS has enabled. For TX this is partly deliberate (the hardware auto-computes the checksum once `SFR_TXCOE_CTL` is enabled at link-up; there's no existing per-packet toggle), but the practical effect is that `ifconfig -txcsum` has no observable effect on the wire — the OS's request to disable the capability is silently ignored rather than honored. Not yet decided whether this needs a fix (toggle `SFR_TXCOE_CTL` based on the mask) or is acceptable as-is — flagged for a decision, not yet scoped as work.

### M6j — Runtime MAC address override (implemented and validated 2026-06-23)

`IOUserNetworkEthernet` declares a dedicated override pair for this — `getHardwareAddress(ether_addr_t *addr)` / `setHardwareAddress(ether_addr_t *addr)` (both `LOCALONLY NDK_21`, `NetworkingDriverKit.framework/Headers/IOUserNetworkEthernet.iig`) — with `setHardwareAddress`'s doc comment explicit that "the driver can override this function if there's a need to re-program the Hardware address... if that feature is needed the driver is expected to override this method." Previously neither was overridden — the MAC was written to `SFR_NODE_ID` only once, in `Start()`, from the value read at boot, with no path for the OS to change it afterward.

Both reference drivers support this. Linux: `ndo_set_mac_address = aqc111_set_mac_addr` (`notes/aqc111.c:647`), which validates via `eth_mac_addr()` and writes `SFR_NODE_ID` via `AQ_ACCESS_MAC`. The x86 kext: confirmed by disassembly (2026-06-22) — `AqPacificDriver::setHardwareAddress(IOEthernetAddress const*)` is a real override of `IOEthernetController::setHardwareAddress`, forwarding to `AqUsbHal::setMacAddress(unsigned char const*)`, which issues the exact `StandardUSB::DeviceRequest` already documented in `RE_LOG.md` "Set MAC Address" (raw `0x0006000600100140` — OUT, `AQ_ACCESS_MAC`, `wValue=0x0010`/`SFR_NODE_ID`, 6 bytes).

**Implementation:** `getHardwareAddress`/`setHardwareAddress` added to `AQC111NIC.iig`/`.cpp`. `setHardwareAddress` validates, writes the new address to `SFR_NODE_ID` via the existing `aqWrite` path, and updates `ivars->macAddress`; `getHardwareAddress` returns that cache.

**Validated end-to-end** (full trail in `TESTING.md` "Runtime MAC Address Override"): negative control confirmed broken beforehand (`EADDRNOTAVAIL` on `ifconfig ... lladdr`, with link-state and OS-wide-block alternatives both ruled out); positive test after implementation showed the override called, the `SFR_NODE_ID` write succeeding, `ifconfig` reflecting the new address, a fresh DHCP lease, and — the rigor standard used for RX/TX checksum and VLAN — a remote-side capture confirming the new address live on the wire. Also confirmed the override is volatile across a genuine power cycle (reverts to the factory address), not a durable EEPROM rewrite — see `TESTING.md` for the investigation; a same-host re-enumeration without an actual power disconnect was not sufficient to settle that on its own.

### M7 — Advanced hardware features (planned, post-stability)

- TSO (TX descriptor MSS field, bits 46:32)
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

### M9 — RX/TX copy-path comparison across this driver, Linux, and the x86 kext (planned, performance, not started)

Originated from investigating whether `IOUSBHostInterface::CreateIOBuffer()` (documented to avoid USB DMA bounce-buffering, vs. the generic `IOBufferMemoryDescriptor::Create()` this driver uses today for all RX/TX/ITR buffers) is worth switching to. Broadened into comparing how many real payload copies each of the three RX implementations actually does, since that turned out to be a bigger and more concrete effect than the bounce-buffer question alone.

**Two independent layers, not one:**

**Layer A — application-level copy (driver code explicitly copying packet payload bytes).** Confirmed directly from source/disassembly for all three:
- **x86 kext: zero payload copies.** `Rx::refill()` calls `mbuf_allocpacket(0x10000, &mbuf)` to allocate a **fresh** 64KB mbuf chain on *every* refill cycle (never reused in-place), wraps that fresh mbuf's own memory ranges directly via `IOMemoryDescriptor::withAddressRanges()`, and hands that straight to `AqUsbHal::performUrb()` — the USB bulk IN transfer DMAs directly into the mbuf that will later be parsed. `Rx::clean()` then extracts each individual packet via `mbuf_split()` (manipulates mbuf chain pointers/headers, never touches the underlying cluster bytes) before handing it to the network stack. The only copy anywhere in this path is an 8-byte `mbuf_copydata()` read of the aggregation header/descriptor metadata — not payload.
- **Linux (`aqc111_rx_fixup`): one copy per packet.** `new_skb = netdev_alloc_skb_ip_align(...); memcpy(new_skb->data, skb->data, pkt_len);` — the generic `usbnet` core owns and recycles its per-URB `skb`, so the fixup callback has no choice but to copy each sub-frame out before returning.
- **This driver: one copy per packet**, for the same structural reason as Linux — `ivars->rxBufs[slot]` is reused in-place and must be reposted to the pipe immediately, so `OnRxComplete` does `pool->allocatePacket(&pkt)` + `memcpy(dst, frame, frame_len)` per frame rather than handing off the raw buffer.

The x86 kext's zero-copy result isn't a cleverer implementation of the *same* approach — it's a different strategy entirely (allocate fresh every cycle, rely on BSD's own efficient mbuf allocator/cache instead of a manually-managed reused buffer pool, plus `mbuf_split`'s zero-copy chain-splitting). This driver and Linux both copy for the identical underlying reason (a reused, must-immediately-repost buffer), so this driver isn't doing anything unusual relative to the actively-maintained reference — only relative to the older, differently-architected kext.

**Layer B — does the USB bulk transfer itself get bounce-buffered by the underlying USB/IOKit DMA machinery, independent of Layer A?** This is the original `CreateIOBuffer` question, and it's a genuinely separate axis from Layer A — a driver could have zero Layer A copies and still incur a Layer B bounce copy, or vice versa. Checked against Apple's own `IODMACommand.iig` doc comment: **"IODMACommand does not perform bounce buffering"** — it maps an `IOMemoryDescriptor` for DMA via `PrepareForDMA` (returning physical address/length segments), and explicitly states that if bounce-buffering is needed at all, it's something the driver sets up itself via `PerformOperation`, moving data to/from a driver-allocated bounce buffer — `IODMACommand` never silently inserts one. This means the public, documented DMA-mapping layer doesn't bounce by itself regardless of which `IOBufferMemoryDescriptor` allocator was used upstream. `CreateIOBuffer`'s actual benefit is therefore more likely about proactively satisfying whatever physical/alignment/segment-count constraints the specific USB host controller driver checks for, versus a generic buffer that might occasionally violate one of those constraints and trigger a fallback bounce path *inside that controller driver* — a layer below `IODMACommand`, inside Apple's closed kernel-side host-controller code, not visible from any public DriverKit header. That would be a conditional/sometimes difference depending on physical memory allocation luck, not a guaranteed always-bounces-vs-never-bounces difference. Not pursued further — would require RE of Apple's closed host-controller kext to resolve definitively. Worth noting this opacity is symmetric: neither the x86 kext era nor Linux's host-controller stack is any more visible to us, so there's no current evidence this driver is specifically worse off at Layer B than either reference, only that it's unconfirmed for all three alike.

**Not yet investigated:** the equivalent comparison for the TX path (this driver's `txDrainOne`, Linux's `aqc111_tx_fixup`, and the x86 kext's `Tx::transmit()` — which uses the pre-allocated `mbuf_alloccluster` pool plus a per-frame `IOMemoryDescriptor::withAddressRanges()`, per `RE_LOG.md` "TxRing layout").

**If Layer A is ever worth closing:** would mean investigating whether `IOUserNetworkPacketBufferPool`/`IOUserNetworkPacket` (or the underlying `IOBufferMemoryDescriptor`/`IOMemoryDescriptor` APIs available to a DriverKit dext) support anything like `mbuf_split` — wrapping an existing buffer's sub-range as a new packet object without copying. Not researched yet; no indication either way whether Skywalk's packet model supports this.

### Bug fix plan — RX stall recovery gaps (confirmed root cause, 2026-06-18, awaiting more occurrences before implementing)

**Symptom** (see README "Current bugs" #2): RX silently stops delivering frames mid-session; TX keeps working; recovery requires unplugging/re-enumerating the device. Recurred 4 times in one day (2026-06-18). Logs saved at `notes/rx_stall_occurrence_{1,2,3}.log` and `notes/rx_stall_occurrence_4_power.log`.

**Likely trigger identified, occurrence 4:** preceded by `DK: IOUserServer(...)::systemPower(0x11) effective 0 current 1` — a system sleep/power-state transition. `SetInterfaceEnable(0)` fires, `hwOnLinkDown`'s first register write returns `kIOReturnNotResponding` as the device powers down, teardown finishes, then 44s of total silence (machine asleep). On wake, `hwEnable` resumes and hits one more `NotResponding` (unchecked, ignored), RX/ITR rearm and recover cleanly — but TX hits exactly the already-diagnosed gap below and **stays stalled for 7+ seconds across multiple retries** in this capture, never self-recovering. This reframes the trigger from "random bus hiccup" to "sleep/wake (or USB power management) reliably exercises this code path" — worth testing explicitly via deliberate sleep/wake cycles rather than waiting for it to recur incidentally.

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

### Bug fix plan — RX aggregation header layout guessing (found 2026-06-22, fixed 2026-06-23)

**Symptom:** none observed as a live failure — found by code review, confirmed by live-traffic instrumentation before fixing.

`parseRxLayout` previously tried three candidate header layouts in sequence and accepted whichever validated against the descriptor count/length sanity checks:
1. 4-byte header at offset 0, packet data starting at offset 4
2. 8-byte header at the last 8 bytes, packet data starting at offset 0
3. 4-byte header at the last 4 bytes, packet data starting at offset 0

The Linux driver (`notes/aqc111.c:1088-1100`, `notes/aqc111.h:214-216`) settles this unambiguously: the descriptor header is **always** an 8-byte field (`u64 desc_hdr`) at the very end of the transfer (`skb_trim(skb, skb_len - sizeof(desc_hdr))`), and packet data always starts at offset 0. `AQ_RX_DH_PKT_CNT_MASK` (`0x1FFF`) / `AQ_RX_DH_DESC_OFFSET_MASK` (`0xFFFFE000`, shift 13) matched this driver's existing bit math exactly — candidate 2 was the only layout with any evidentiary support.

**Confirmed before fixing:** added one-shot-free logging of which candidate matched on every `OnRxComplete`, ran real traffic. Candidate 2 matched on every single completion; candidates 1 and 3 never matched once. Fixed with that evidence in hand rather than on the Linux reference alone.

**Where the original "disagreement" actually came from:** the multi-candidate hedge existed because the x86 kext's RE notes (`RE_LOG.md`, since corrected) claimed the header was at offset 0 — seemingly contradicting Linux. Re-disassembling `Rx::clean()` directly (`otool -tV` on `~/trendiokit/Contents/MacOS/TUC-ET5G`) showed that claim was simply wrong: the kext reads the header via `mbuf_copydata(mbuf, total_length - 8, 8, &local)` — the same tail-8-byte offset Linux uses, not offset 0. The earlier RE pass had paraphrased a `copydata`-style call without tracing the register dataflow that computed its offset argument, and that error propagated into this driver's "hardware revisions disagree" comment and the defensive multi-candidate parsing it justified. There was never an actual conflict between the two reference drivers — `RE_LOG.md`'s RX buffer layout section is now corrected to match.

**Second, related bug, fixed in the same pass:** Linux pads each packet to an 8-byte boundary when walking the buffer (`pkt_len_with_padd = (pkt_len + 7) & 0x7FFF8`, `notes/aqc111.c:1128`). This driver's packet-walk loops — both the validation loop inside `parseRxLayout` and the consumer loop in `OnRxComplete` — previously advanced by raw, unpadded `pkt_len`, which would have misparsed any aggregated buffer carrying more than one packet.

**Fix applied:** `parseRxLayout` now only implements the confirmed tail-8-byte-header/data-at-0 layout (the multi-candidate trial and the `candidate` diagnostic field are gone). All three packet-offset advances (`parseRxLayout`'s validation loop, plus both `continue` paths and the success path in `OnRxComplete`) now use `(pkt_len + 7u) & ~7u` instead of raw `pkt_len`.

---

### Bug fix plan — AMALL fallback can never be retracted once triggered by address-count overflow (found 2026-06-23, confirmed reproduced 2026-06-23, fixed and validated 2026-06-23)

**Symptom:** none observed as a live failure in the wild yet — found by reasoning through the M6h implementation's design after validating it, then confirmed reproduced deliberately before it could cause real harm in the wild.

**Reproduced (2026-06-23):** temporarily lowered `AQ_MAX_MCAST_ADDRESSES` to `10`. Joined 5 extra multicast groups on top of macOS's standing ~7-8, pushing `count` to 12 and triggering the fallback (`RX_CTL=0x029a`, `AMALL` set). Sent a frame to a deliberately non-colliding address (`01:00:5e:7f:03:01`, hash bucket 2, confirmed clear of every bucket seen this session) — admitted, as expected with `AMALL` active. Then dropped all 5 extra groups, bringing `count` back to `7` (well under the threshold) — the driver correctly recomputed and wrote a fresh 7-entry hash table (`filter=00 c0 00 82 00 40 01 40`), but `RX_CTL` stayed at `0x029a` — `AMALL` was never cleared. Re-sent the identical `01:00:5e:7f:03:01` frame: still **admitted**, even though it's absent from the fresh table and `count` is well within hash-table capacity — admission can only be explained by the stuck `AMALL` bit. Bug confirmed exactly as predicted.

`SFR_RX_CTL_AMALL` (accept-all-multicast) has two independent triggers in the current implementation: an explicit `SetAllMulticastModeEnable(true)` call, and `doSetMulticastAddresses()` falling back to it when the OS hands over more multicast groups than `AQ_MAX_MCAST_ADDRESSES` (64) can represent precisely in the hash table. Both triggers currently just OR the same bit into `ivars->rxFilterBits` — there's no way to tell, later, *which* trigger is responsible for it being set.

This matters because the two triggers clear very differently in practice. The explicit form is cleared by the OS itself calling `SetAllMulticastModeEnable(false)` when its own `IFF_ALLMULTI`-equivalent state changes. The overflow form has no equivalent natural clear: the OS has no reason to ever call `SetAllMulticastModeEnable(false)` to undo a fallback *we* decided on internally — it doesn't know we made that decision. So once the multicast group count briefly exceeds 64 even once, `AMALL` would stay set **permanently**, even after the count drops back to something the 64-bucket hash table could represent precisely again. That's a real, lasting performance regression (every multicast frame on the network gets pushed up to the host indefinitely, not just the groups actually joined), not a cosmetic gap — caught by reasoning about the lifecycle, not by the validation testing already done in M6h, which only exercised the overflow→ON transition, never the count-drops-back-down direction.

**Fix applied:** tracks the two triggers in separate ivars — `allMulticastRequested` for the explicit call, `mcastCountExceeded` for the overflow fallback — instead of a single shared bit, and recomputes `SFR_RX_CTL_AMALL` as the OR of both via a shared `recomputeAmallBit()` helper called on every change to either. `doSetAllMulticastMode()` updates `allMulticastRequested`; `doSetMulticastAddresses()` updates `mcastCountExceeded` based on the *current* call's `count` (so it correctly flips back to `false` once count drops under the threshold) before the early-return that skips the hash-table write. This lets the overflow contribution retract on its own once the count drops back under the threshold, without touching an independently-active explicit request.

**Validated (2026-06-23):** repeated the exact reproduction above (`AQ_MAX_MCAST_ADDRESSES` still lowered to `10`, joined 5 extra groups → `count=12` → `AMALL` engaged, `RX_CTL=0x029a`; confirmed `01:00:5e:7f:03:01` admitted). Dropped the 5 groups again → `count=7`, fresh 7-entry table written — this time `RX_CTL=0x0298`, `AMALL` correctly cleared (versus the buggy version's stuck `0x029a`). Re-sent the identical `01:00:5e:7f:03:01` frame: no longer captured by `tcpdump` at all — confirms the retraction at both the register level and actual frame-admission behavior, not just one or the other. Restored `AQ_MAX_MCAST_ADDRESSES` to `64` afterward. Not separately re-tested: an explicit `SetAllMulticastModeEnable(true)` holding `AMALL` on independently through an unrelated count drop — the code path makes this trivially true (the OR in `recomputeAmallBit()` means either flag alone is sufficient), but it hasn't been exercised on real hardware.

---

### M10 — TCP Segmentation Offload (TSO4/TSO6) (implemented on branch `tso-offload`; core validation passed 2026-07-03)

**Status (2026-07-03):** engagement (`segsz=1448`, super-packets ≫ MTU in `txDrainOne`), wire segmentation (1514-byte frames / 1448-byte payloads captured with peer GRO disabled), and end-to-end integrity (1 GiB random file, SHA-256 match both ends, 414 MB/s through the TSO path; plus a second 1 GiB run under 0.5% induced ingress loss via IFB+netem — ~3,600 macOS retransmissions through RACK/SACK recovery, hash still matching, exercising the segmenter on retransmit-boundary segment sizes) all validated — see `notes/tso_validation_gro.md` and `notes/tso_sha256_validation.md`. **Beware the GRO capture trap** documented in the former: a Linux receiver re-coalesces TCP segments in software before tcpdump's tap, making correct TSO look like oversized wire frames — `ethtool -K <if> gro off` (and `rx-gro-hw off`) before interpreting packet lengths. Investigation byproducts kept: Linux-parity 8-byte TX padding + DROP_PADD (we were out of spec before, independent of TSO); BM/ARC link-up zeroing (registers read back already-zero — inert parity). TSO6/IPv6 also validated same day (fd00:111::/64 bench pair, `flags=0x200000`, MSS 1428 reflecting the 40-byte IPv6 header, 1514-byte wire frames with peer GRO off, 1 GiB SHA-256 match). TSO4 × software VLAN also validated (see `notes/tso_vlan_validation.md`): inline 802.1Q tag in the template, segmenter parses past it, 1518-byte tagged wire frames with correct checksums, 1 GiB SHA-256 match. All merge gates cleared 2026-07-03 (BM/ARC probe logging demoted to plain parity writes). Deferred TODOs, not gates: strict pcap invariant script (IP ID/seq/flags per-burst assertions — sha256 clean/lossy/VLAN/v6 runs cover correctness in aggregate); iperf3+CPU comparison (belongs to the general performance/benchmarking work item).

**What the hardware does:** the device segments one oversized "super-packet" (a single TCP/IP header set + up to 64KB payload) into MSS-sized wire frames itself — replicating the header template per segment and patching IP total length/ID/checksum, TCP seq, TCP flags (FIN/PSH last-only), and TCP checksum via the same engine as `SFR_TXCOE`. Driver-side cost is one field: **MSS in TX descriptor bits 46:32** (`AQ_TX_DESC_MSS_MASK 0x7FFF`, shift 32, per Linux `aqc111.h`). Linux (`aqc111.c` `netif_set_tso_max_size(65535)`, two lines in `tx_fixup`) and the x86 kext (imports only `mbuf_get_tso_requested`) both use it; no TSO-specific SFR register exists — it rides on the TX checksum engine already enabled.

**The OS contract:** the stack only hands TSO packets for capabilities advertised (`kIOUserNetworkHWAssistTSO4/6`): plain TCP over IPv4/IPv6, no IPv4 options / IPv6 extension headers, total ≤ the `tso_mtu` we report via `getTSOOptions()`, MSS in per-packet metadata (`IOUserNetworkPacket::getTSOInfo(&segsz, &flags)` — segsz==0 means not TSO). Delivered inside our own pool buffers, so size is guaranteed by construction. Darwin's gating conditions are readable in XNU `tcp_output.c` (open source — OK to cite anywhere per doc policy).

**Implementation (branch `tso-offload`):**
- `AQC111_HWASSIST_MASK` += `kIOUserNetworkHWAssistTSO4 | TSO6` (declared via `getFeatureFlags()`, self-initialized enabled mask — same negotiation pattern as M6a).
- `getTSOOptions()` override (LOCALONLY, plain C++ — not IMPL) reports `tso_mtu4/6 = 65535` (`AQC111_TSO_MAX_IP_LEN`, Linux parity).
- `txDrainOne`: `getTSOInfo()`; when `segsz > 0`, allow `dataLen` up to `AQC111_TSO_MAX_FRAME_LEN` (65535 + Ethernet + VLAN headers) instead of the MTU-derived cap, and OR the MSS into descriptor bits 46:32.
- Memory plumbing (the real cost): `poolOptions.bufferSize` and `AQC111_TX_BUF_SIZE` raised from ~16KB (`AQC111_MAX_FRAME_LEN`) to `AQC111_TSO_MAX_FRAME_LEN` (~64KB). Pool = 64 buffers → ~4MB (was ~1MB). If that's ever offensive, `AQC111_TSO_MAX_IP_LEN` can shrink (even 16KB retains most of the per-transfer win) — it's a driver-declared limit, not a hardware constant.

**Verification plan (TESTING.md evidence when done):**
1. Engagement: `LogD` TSO line in `txDrainOne` showing `segsz>0` with `dataLen` ≫ MTU; `ifconfig -v` shows TSO4/TSO6 hwassist.
2. Wire correctness: tcpdump on the bench peer during bulk TX; script asserts per-burst invariants — all segments MSS-sized except last, seq cumulative with no gap/overlap, IP ID incrementing, valid IP+TCP checksums per frame, PSH/FIN only on final segment.
3. Integrity: multi-GB transfer + sha256 both ends; a lossy-path run for retransmission interaction.
4. Edge cases: payload exact multiple of MSS; IPv6; **TSO × software VLAN** (inline tag becomes part of the replicated header template — should work, must verify on fw 130.5.32).
5. Perf: iperf3 TX throughput + dext CPU vs baseline — expect a real win (per-USB-transfer and per-packet-RPC count drops ~44× for full-size bursts), unlike M9's expected-flat result.

**Risk notes:** device-side segmenter is firmware-driven — bugs would appear as corrupted streams (integrity test covers). The 15-bit MSS field caps segsz at 32767 (fine — real MSS ≤ 9K). `RX_BUF_SIZE` (USB transfer staging) is unrelated and unchanged.

---

### M11 — Wake-on-LAN (magic packet) (planned, 2026-07-03, not started)

Three stacked problems, easiest first:

**Layer 1 — device arming (documented, low risk).** Linux `aqc111_suspend` is
the complete recipe. WoL armed: quiesce RX, then leave a minimal RX path
alive (`RX_CTL=AB|START`, `BM_INT_MASK=0`, `BMRX_DMA_CONTROL=0x80`
[BMRX_DMA_EN — the suspend-path value], `ETH_MAC_PATH=RX_PATH_READY`, minimal
bulk-in queue config, `MEDIUM_RECEIVE_EN`), write `wol_cfg` (MAC + flags,
`AQ_WOL_FLAG_MP=0x2`) via `bRequest 0x60` (AQ_WOL_CFG), set `AQ_WOL` (bit 20)
in phy_cfg via `bRequest 0x61` (our FWPhyAccess path). Resume: clear
`SFR_MONITOR_MODE` wake bits (EPHYRW/RWLC/RWMP/RWWF/RW_FLAG). x86 kext
corroborates and adds a key design fact (RE_LOG.md): on WoL resume,
`AqUsbHal::enable()` short-circuits to `phyAccess->sleep(false)` — it does
NOT re-run full `hwStart()`. Wake is not cold re-init.

**RE gap to fill (scoped, symbols known):** the x86 arming half —
`AqPacificDriver::setWakeOnMagicPacket(bool)` (0x2b5a),
`AqPacificDriver::setPowerState` (0x2cd0) + `myPowerStates` table (0x4f10),
`AqUsbHal::hwPrepareSleep` (0xf72) / `hwFinishSleep` (0xc46),
`FWPhyAccess::sleep(bool)` (0x7ca). Same `xcrun llvm-objdump -d --demangle`
technique that decoded `Tx::transmit` TSO handling. Findings → RE_LOG.md
(x86 kext scope, so RE_LOG is the right home).

**Layer 2 — DriverKit plumbing (the real unknown).** API surface exists:
`SetWakeOnMagicPacketSupport(bool)` LOCALONLY (capability declaration),
`SetWakeOnMagicPacketEnable(bool)` (deprecated-capital PURE VIRTUAL — stub
owed regardless; likely another capital-vs-lowercase which-gets-called trap
à la M6f/hwassists), `kIOUserNetworkFeatureFlagWOMP` (0x04000000), and
`IOService::SetPowerState`/`ChangePowerState`. Open question nobody
documents: what PM transitions a NIC dext actually receives on system sleep,
and whether there's a hardware-access window for our EP0 arming writes
before the USB device is suspended (Linux does this in `suspend()` with
`_nopm` variants; the dext equivalent is unverified).

**Layer 3 — platform reality (the fussy part).** USB remote-wakeup grant
(`SetFeature(DEVICE_REMOTE_WAKEUP)` — presumably the USB family's job once
wake interest is expressed; unverified), port power through sleep
(dock/hub-dependent — kills WoL on many TB docks), Apple Silicon wake policy
(`pmset womp`, AC-power conditions, DarkWake vs full wake).

**Phase 0 RESULTS (2026-07-04, four genuine sleep/wake cycles captured via log collect):**
- Sleep: `SetInterfaceEnable(false)` fires FIRST; `AQC111-A SetPowerState(Off)`
  lands mid-disable; `AQC111-NIC SetPowerState(Off)` lands ~15ms later, AFTER
  hwDisable completes. Every EP0 control transfer in the window succeeds
  (whole hwOnLinkDown/hwDisable sequence returns 0x0) — the arming window
  exists and is proven.
- Wake: **SetPowerState(On) FIRES ON EVERY WAKE** — proven by cumulative
  counters (2026-07-04 second capture: off/on stayed in lockstep across four
  sleep/wake cycles, plus one initial On at attach), after the first capture
  falsely suggested it never fired. Every single On LOG LINE was lost to
  early-wake log loss (5 deliveries, 0 lines captured) — the counter carried
  in later reliable lines was the only truthful witness. Wake ordering:
  SetPowerState(On) → SetInterfaceEnable(true) → hwEnable → link-up (the
  `pmCounters at enable` readout was already incremented). The PM hook pair
  is fully symmetric; WoL disarm may use SetPowerState(On) or the existing
  applyPhyAdvertise overwrite — both are available.
- Design consequence: arm WoL in NIC `SetPowerState(Off)` (sleep-specific,
  post-hwDisable; overwrite the just-written lowPower phy_cfg with AQ_WOL
  per the x86 mutual-exclusivity finding + write WOL_CFG). Disarm needs no
  new code: hwEnable's applyPhyAdvertise (0x032b000f, bit 20 clear) already
  rewrites phy_cfg without AQ_WOL on every wake.
- TCPKeepAlive maintenance DarkWakes fully cycle disable/enable — free
  repeated stress of the arm/disarm path.
- Capture methodology that worked: dext logs are stream-only (never persisted
  to the log archive); `sudo log collect --last N` right after wake snapshots
  the in-memory buffers. Validity gate: `pmset -g log` must show real
  "Entering Sleep state" (not DarkWake bounce — first attempt was a 3-second
  DarkWake killed by HID, a false negative).

**Phasing:**
0. **PM transparency (do first, pays twice):** instrument
   `SetPowerState`/`Stop`/interface messages and log everything that fires
   across a sleep/wake cycle, before writing any WoL code. This is also the
   diagnostic infrastructure the open RX-stall-on-sleep/wake incident needs.
1. x86 `hwPrepareSleep` RE + device-side arming from whatever hook phase 0
   proves we get.
2. Capability/toggle plumbing (Support + Enable stub + WOMP flag; verify
   which API generation the OS calls).
3. Bench validation: `pmset womp 1`, sleep on AC, `wakeonlan`/`etherwake`
   from the peer, confirm wake + wake-reason via `pmset -g log` /
   `log show` "Wake reason"; negative control with WoL disabled; direct-port
   vs dock-port comparison.

## Log Level Strategy (implemented, on branch `log-level-strategy`)

DriverKit's `os/log.h` only exposes `OS_LOG_TYPE_DEFAULT` (no `os_log_debug`/`info`/subsystem API), so verbosity filtering is done in our own code: four level-gated macros (`LogE`/`LogI`/`LogD`/`LogV`) backed by a single `gLogLevel`, replacing the single `Log()` macro that previously fired everything — including per-frame hex dumps — at full volume. All call sites in `AQC111NIC.cpp`/`AQC111.cpp` reclassified: hex dumps → Verbose, per-completion bookkeeping → Debug, lifecycle → Info (default), failures → Error (always on).

**Load-time config — confirmed working (rounds 1 & 2 tested):** `AQC111LogLevel` integer key in each `Info.plist` personality dict, read via `CopyProperties()` in `Start()`. Round 1 confirmed the absent-key fallback defaults correctly to Info. Round 2 confirmed setting the key to `3` (Verbose) and rebuilding actually raises the level. Shipped default is `1` (Info), set explicitly in both personalities.

**Live config — implemented and confirmed working via `IOUserClient`.** The supported DriverKit IPC surface is `IOServiceOpen(service)` → that service's `NewUserClient()` → `IOUserClient::ExternalMethod()`. `AQC111NIC::NewUserClient()` creates a small `AQC111LogUserClient` from the NIC personality's `AQC111LogUserClientProperties` plist entry (`IOClass=IOUserUserClient`, `IOUserClass=AQC111LogUserClient`, `IOUserClientEntitlements=false`). `tools/set-log-level.swift` matches `IOClass=IOUserNetworkEthernet` plus `IOPropertyMatch={ IOUserClass=AQC111NIC }`, opens the NIC service, and calls selector `0` via `IOConnectCallScalarMethod()` with one scalar (`0=Error`, `1=Info`, `2=Debug`, `3=Verbose`). The user client validates the scalar and updates the NIC-local `gLogLevel`; confirmed by kernel logs showing debug/verbose TX logs stop after setting level `1`.

Important finding: opening the plain `AQC111` USB-device personality creates a user client in the wrong control domain for this purpose. It logs that `AQC111SetNICLogLevel()` ran, but the active NIC TX/RX path can still read a separate `gLogLevel` value. Do not rely on C++ globals being shared across DriverKit personalities. The live-control endpoint must be opened on `AQC111NIC`, where the hot-path logs actually run.

The first attempted live path, `IORegistryEntrySetCFProperties()` against the `AQC111NIC` service, consistently returned `0xe00002c7` (`kIOReturnUnsupported`) before reaching the override. The suspected `UserSetProperties(OSContainer*) LOCAL` alternate is present in generated SDK headers but gated behind `PRIVATE_WIFI_ONLY` in `IOService.iig`, so it is not a usable public DriverKit override. Keep live diagnostics on `IOUserClient`.

---

## Known Risk Points

| Area | Risk | Mitigation |
|------|------|-----------|
| M6: RX CTL cycling | hwOnLinkUp must stop then restart RX precisely; wrong order = no RX | Mirror Linux `aqc111_rx_fixup` / link-up sequence exactly |
| M6: DHCP | Requires correct ARP handling (already working) + IP stack integration | Should work once static-IP ping is solid |
| General | Corpse budget (~2 unplug cycles/boot) exhausts quickly | Plan test runs to minimize unplugs; reboot to reset |
| M6a/M6b: TODO | `SFR_RXCOE_CTL`/`SFR_TXCOE_CTL` never cleared in `hwDisable()` — sticky across dext Stop/Start, harmless today since `hwOnLinkUp` always rewrites them correctly on next enable, but leaves hardware in an undefined state on teardown (see `TESTING.md` "Reusable Methodology Notes") | Investigate later whether `hwDisable()` should explicitly zero both registers |
| M6f: TODO | `SetInterfaceEnable` and `SelectMediaType` (deprecated capital forms) are the only overrides implemented for those two; their lowercase modern equivalents (`setInterfaceEnable`, and `handleChosenMedia` for media — note `handleChosenMedia` is itself already implemented as the *primary* path, this row is about `SelectMediaType` staying a no-op stub alongside it) aren't wired to call the same logic. Confirmed empirically which variant the OS actually calls for each (legacy wins for interface-enable, modern wins for media) — not currently broken, but inconsistent with the "implement both forms via one shared helper" policy adopted for M6g/M6h's promiscuous/multicast work (both already done there), and fragile if a future macOS/NDK release shifts which variant Skywalk calls | Retroactively factor both into shared helpers, lower priority since both are confirmed working as-is |

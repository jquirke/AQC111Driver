# Testing Log

Test methodology and results for features where "it compiled and the happy
path works" isn't sufficient evidence. Design rationale lives in
`IMPL_PLAN.md`; this file is the record of what was actually run and what
it proved. Organized by feature, newest entries at the top of each section.

---

## Runtime MAC Address Override

### Negative control (2026-06-23): confirmed broken before implementation

Before adding any override, `setHardwareAddress`/`getHardwareAddress` did not exist anywhere in `AQC111NIC.iig`/`.cpp` — the MAC was only ever written to `SFR_NODE_ID` once, at `Start()`, from the value read at boot.

```text
$ ifconfig en9 | grep ether
    ether 3c:8c:f8:f9:d7:a3
$ sudo ifconfig en9 lladdr 02:11:22:33:44:55
ifconfig: ioctl (SIOCAIFADDR): Can't assign requested address
```

Ruled out link state as the cause before concluding it was the missing override: taking the interface down first made it fail *earlier* (`ENETDOWN`) rather than succeed, and bringing it back up reproduced the identical `EADDRNOTAVAIL`. Also checked whether this was a macOS-wide block rather than a missing override: attempting the identical address change against a completely different interface (`en6`, different hardware/driver) failed with the same `SIOCAIFADDR`/`EADDRNOTAVAIL` error. That result alone was ambiguous on its own (could mean either "OS-wide block" or "that other driver also doesn't implement the override") and got resolved by the positive result below.

### Implementation

Added `getHardwareAddress(ether_addr_t *addr)` / `setHardwareAddress(ether_addr_t *addr)` overrides (`LOCALONLY`, matching the declared pair in `IOUserNetworkEthernet.iig`). `setHardwareAddress` validates, writes the new address to `SFR_NODE_ID` via the existing `aqWrite` path, and updates the cached `ivars->macAddress`; `getHardwareAddress` returns that cache. See `IMPL_PLAN.md` M6j.

### Positive validation (2026-06-23): full end-to-end success

```text
log: setHardwareAddress: write SFR_NODE_ID -> 0x0
$ ifconfig en9
en9: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    ether 3c:8c:f8:f9:d7:a4
```

- DHCP issued a fresh lease for the new address — the server treated it as a distinct client, independent corroboration that this is a real MAC change, not a stale `ifconfig` cache (see "Reusable Methodology Notes" below on `ifconfig`/aggregate counters not being trustworthy on their own).
- Local `tcpdump -i en9` showed the new address (`3c:8c:f8:f9:d7:a4`) as the actual source MAC on live ARP and TCP traffic.
- **Remote-side capture** (the rigor standard used for RX/TX checksum and VLAN — a local capture on the transmitting host isn't sufficient on its own) confirmed the same address on the wire from an independent vantage point, on real IPv6 MLDv2 multicast traffic:

```text
03:49:58.902594 3c:8c:f8:f9:d7:a4 > 33:33:00:00:00:16, ethertype IPv6 (0x86dd), length 110: :: > ff02::16: HBH ICMP6, multicast listener report v2, 2 group record(s), length 48
```

### Persistence investigation (2026-06-23): volatile across a genuine power cycle, not an EEPROM rewrite

After the positive result above, a re-enumeration showed `Start()`'s flash-MAC read (`AQ_FLASH_PARAMETERS`, bRequest=0x20, logged as `"Start: readMAC -> ..."`) reporting back the *override* (`...a4`), not the original factory value (`...a3`) — initially read as evidence that `SFR_NODE_ID` writes durably rewrite whatever EEPROM-backed storage `AQ_FLASH_PARAMETERS` reads from. **Exactly what kind of re-enumeration produced that reading (whether the device genuinely lost power or not) was not conclusively established** — flagged here rather than asserted, since the next test is what actually settled the question.

Restored the original address (`sudo ifconfig en9 lladdr 3c:8c:f8:f9:d7:a3`) and tested again with a **deliberate re-enumeration that included a real power disconnect**. Result: `Start: readMAC` reverted to the genuine factory value (`...a3`), not whatever was set immediately beforehand.

**Conclusion:** a true power cycle reverts the override, so the factory EEPROM itself is not durably rewritten by this feature. The most likely explanation for the earlier `...a4` reading is that `AQ_FLASH_PARAMETERS` doesn't necessarily re-read raw EEPROM cells on every call — it may return a firmware-side cache that's only reloaded from real EEPROM at power-on, with `SFR_NODE_ID` writes updating that same cache operationally; a re-enumeration that doesn't fully power-cycle the chip would leave that cache (and the override) intact. This is a plausible explanation for the discrepancy, not a confirmed mechanism — what's actually confirmed is the end result (power-cycle reverts it, soft reset apparently doesn't), which is the practically important property regardless of the exact internal reason. This makes the override safe and power-cycle-scoped, not a risk of permanently overwriting the device's factory-assigned address — but confirming that required an actual power-disconnect test; a same-host logical re-enum alone was not sufficient to settle it, consistent with the general "SFR registers stay sticky absent a real power-cycle" caution in "Reusable Methodology Notes" below.

### Conclusion

Runtime MAC override works end-to-end: OS → `setHardwareAddress` → `SFR_NODE_ID` write → confirmed live on the wire from a third-party vantage point, with independent DHCP-server corroboration, and confirmed volatile/safe across an actual power cycle.

---

## Media Selection

### Implementation

The real OS-facing media-selection entry point is `handleChosenMedia(MediaWord)`, not the deprecated `SelectMediaType`. Previously a no-op stub; PHY init always advertised all four rates regardless of what was requested. See `IMPL_PLAN.md` M6f for the full design (single-bit `AQ_ADV_*` mask per forced rate, stored in a new `ivars->phyAdvertiseMask` ivar so it survives a later interface disable/enable, applied via a helper shared with `hwEnable`).

### Baseline regression (2026-06-23): autoneg unaffected by the refactor

Confirmed across three real peers before testing the new forcing behavior, to make sure storing the advertise mask in an ivar and sharing the PHY-write helper between `hwEnable`/`handleChosenMedia` didn't regress plain autonegotiation:

- **1G-only peer:** negotiated `1000 Mbps` (`code=0x11`), full duplex — matches remote `ethtool` (`Speed: 1000Mb/s`, `Duplex: Full`, `Auto-negotiation: on`).
- **5G-capable peer:** negotiated `5000 Mbps` (`code=0x0f`).
- **Live mid-session renegotiation:** restricting the remote's advertisement on the fly (100M → 1000M, no action on this driver's side) flowed cleanly through the existing `hwOnLinkUp` path and correctly re-reported the new speed — confirms the existing link-event handling wasn't disturbed either.
- **2.5G case, restricting the remote side instead of forcing it off:** `sudo ethtool -s <iface> speed 2500 duplex full autoneg on` (multi-gig copper rates have no genuine forced/non-autoneg signaling mode in the IEEE spec at all, so `autoneg on` is required even when restricting to one rate) cleanly negotiated `2500 Mb/s` on the remote, and this driver correctly followed it down to `2500 Mbps` (`code=0x10`).

**Negative finding worth keeping in mind for future interop testing:** first attempted the 2.5G-restriction test by genuinely disabling the remote's autoneg (`ethtool -s <iface> speed 100 duplex full autoneg off`) instead. Result: no link at all (`code=0x19`, an unrecognized speed code, `status: inactive`) — a real-world instance of the classic IEEE 802.3 parallel-detection limitation (an autonegotiating PHY paired with a hard-forced peer can sense speed but not duplex, and many implementations simply fail to establish a stable link rather than degrade gracefully). Recovered cleanly the moment the remote went back to plain `autoneg on`. Not a driver bug — this is exactly mirrored by the fact that this driver's own "forced" mode is the same restricted-advertisement model, not a true forced/non-autoneg mode either (see `IMPL_PLAN.md` M6f).

### Forcing media on this driver's side (2026-06-23)

With the remote left on full autoneg (advertising up to 5G/10G), forced this driver's own side down via `ifconfig` and confirmed it overrides what autoneg alone would pick:

- **`sudo ifconfig en9 media 100baseTX mediaopt full-duplex`** → log: `handleChosenMedia: advertiseMask=0x1` → `applyPhyAdvertise: AQ_PHY_OPS flags=0x032b0001` → link renegotiated to `100 Mbps` (`code=0x13`) despite the remote advertising up to 1000baseT; `ifconfig en9` showed `media: 100baseTX <full-duplex,flow-control>`, `status: active`; traffic flowing normally; remote `ethtool` independently confirmed `Speed: 100Mb/s`.
- **`sudo ifconfig en9 media autoselect`** → `advertiseMask=0xf` → link climbed back to `1000 Mbps` (`code=0x11`), matching the remote's actual max.
- **`sudo ifconfig en9 media 2500base-T mediaopt full-duplex`** (note: macOS `ifconfig`'s media-name table wants the hyphenated `2500base-T`, not `2500baseT`, which errors `unknown media subtype`) → `advertiseMask=0x4` → renegotiated to `2500 Mbps` (`code=0x10`) despite the remote advertising up to 10G. Cross-confirmed independently via the remote's own `ethtool`: `Link partner advertised link modes: 2500baseT/Full` (only 2.5G), `Speed: 2500Mb/s` — direct third-party evidence this driver is genuinely restricting its own advertisement, not just self-reporting a speed it isn't actually negotiating.
- Reverting to `autoselect` again climbed back to `5000 Mbps`, matching this peer's actual max.

### Persistence across interface disable/enable (2026-06-23)

The specific case `ivars->phyAdvertiseMask` was added to handle, rather than leaving the mask as a `hwEnable`-local literal: forced `100baseTX`, then `sudo ifconfig en9 down` followed by `sudo ifconfig en9 up`. Log confirmed `hwDisable` withdrew the advertisement entirely (`AQ_PHY_OPS withdraw advertise flags=0x00000000`) as it always does, but the subsequent `hwEnable` on `up` re-applied the *stored* mask — `applyPhyAdvertise: AQ_PHY_OPS flags=0x032b0001` (mask `0x1`, not `0xf`) — and the link re-negotiated to 100 Mbps again, confirmed by the remote's `ethtool` (`Speed: 100Mb/s`, `Duplex: Full`). Without the ivar, this would have silently reverted to full autoneg on every `ifconfig down`/`up`, the same bug class flagged for M6g/M6h's filter bits.

### Conclusion

Forced media selection works end-to-end across the full rate range this hardware and test peers support (100M/2.5G, plus the pre-existing autoneg path confirmed at 1G/5G), survives an interface disable/enable cycle, and reverting to `autoselect` always climbs back to the link's actual max. Not yet exercised: the half-duplex rejection path (`kIOUserNetworkMediaOptionHalfDuplex` → `kIOReturnUnsupported`) — implemented but not tested against real hardware.

---

## Promiscuous Mode

### Methodology: testing without switch mirroring

Test rig is a direct point-to-point link (no switch in the path), so a frame addressed to a foreign (non-matching, non-broadcast/multicast) destination MAC already reaches this NIC's physical layer regardless of destination — no port mirroring needed. The only open question is whether *this driver's own* hardware filter (`SFR_RX_CTL`, lacking the `PRO` bit by default) drops it before it reaches `OnRxComplete`. Crafted the foreign-MAC frame from the remote Linux peer with `scapy` (`nmap`/`nping`'s `-e <iface>` hit a known long-interface-name limitation with `enx<mac>`-style USB Ethernet names, so used `scapy.sendp()` instead, which has no such limit):

```python
from scapy.all import sendp, Ether, IP, ICMP
sendp(Ether(dst='02:00:00:00:00:99')/IP(dst='1.2.3.4')/ICMP(), iface='enx1c860b3be7f6', count=3)
```

### Negative control (2026-06-23): confirmed broken before implementation

Before adding any real logic, `SetPromiscuousModeEnable` logged and returned success with no hardware effect. Sent the foreign-MAC frame above; confirmed **nothing** appeared in `tcpdump -i en9 icmp` *and* nothing appeared in the dext log (no `OnRxComplete`/`RX[...]` entries) — the hardware filter silently dropped it before the frame ever reached the driver. Note: `SetPromiscuousModeEnable` being *called* (e.g. by running `tcpdump`/Wireshark locally, which requests promiscuous capture mode via BPF regardless of this test) doesn't contaminate this result — the stub didn't touch hardware either way at this point.

### Implementation

Added `ivars->rxFilterBits` and a shared `doSetPromiscuousMode()` helper toggling `SFR_RX_CTL_PRO` (`0x0001`); `hwOnLinkUp` now ORs in the stored bits instead of hardcoding `0x0288`. Implemented both the deprecated capital `SetPromiscuousModeEnable` and the modern lowercase `setPromiscuousModeEnable`, both routing to the same helper. See `IMPL_PLAN.md` M6g.

### Positive validation (2026-06-23)

Enabled promiscuous mode (confirmed empirically this fires through the deprecated capital form, not the lowercase one, on this NDK — see "Known Risk Points" in `IMPL_PLAN.md`):

```text
doSetPromiscuousMode: rxFilterBits=0x0001 (interfaceEnabled=1)
doSetPromiscuousMode: RX_CTL=0x0289 -> 0x0
```

Re-sent the identical foreign-MAC frame — now visible in `tcpdump -i en9 icmp`:

```text
06:13:48.158335 a8:e2:91:12:c6:2b > 02:00:00:00:00:99, ethertype IPv4 (0x0800), length 60: 192.168.0.88 > 1.2.3.4: ICMP echo request, id 0, seq 0, length 8
```

### Negative control, repeated with promiscuous mode off (2026-06-23)

Disabled promiscuous mode (`RX_CTL` back to `0x0288`, `SFR_RX_CTL_PRO` cleared), then re-checked with `tcpdump -n -e --no-promiscuous-mode -i en9 icmp` — the `--no-promiscuous-mode` flag specifically to rule out `tcpdump` itself re-requesting promiscuous capture and contaminating this half of the test. Result: nothing captured, confirming the toggle genuinely controls the behavior in both directions, not just a one-shot positive result.

### Conclusion

Promiscuous mode works end-to-end: OS → `SetPromiscuousModeEnable`/`setPromiscuousModeEnable` → `SFR_RX_CTL_PRO` write → confirmed change in actual frame admission on the wire (not just a register write with assumed effect), in both the enable and disable direction, with the disable direction specifically verified against `tcpdump` self-contamination.

---

## Multicast Filtering

### Methodology

Same direct point-to-point rig as Promiscuous Mode above (no switch needed). Crafted multicast test addresses by picking an administratively-scoped multicast IP and deriving its Ethernet MAC by hand (`01:00:5e` + low 23 bits of the IP), choosing the last octet specifically to land on a hash bucket *not* already occupied by whatever real multicast groups macOS has standing at the time — confirmed by computing the driver's exact CRC32/`bitrev32` hash algorithm in a standalone Python script *before* touching the driver code, so the implementation could be checked against an independent reference rather than just "does it look plausible."

### Negative control (2026-06-23): confirmed broken before implementation

Before adding real logic, `SetAllMulticastModeEnable`/`SetMulticastAddresses` logged and returned success with no hardware effect. Sent a frame to a derived multicast MAC (`01:00:5e:7f:01:63`, IP `239.255.1.99`) via `scapy`; confirmed nothing in `tcpdump` or the dext log.

### Implementation

`doSetAllMulticastMode()` toggles `SFR_RX_CTL_AMALL`. `doSetMulticastAddresses()` computes the CRC32/`bitrev32` hash bucket for each address (logging the byte/bit breakdown per address for runtime visibility), writes the 8-byte table to `SFR_MULTI_FILTER_ARRY`, toggles `SFR_RX_CTL_AM`, and falls back to `AMALL` instead of a partial table when the OS hands over more groups than `AQ_MAX_MCAST_ADDRESSES` (64, matching Linux) can represent — mirroring Linux's mutual exclusion exactly, not an additive/always-write-the-table approach. See `IMPL_PLAN.md` M6h.

### Positive validation — per-address hash filtering (2026-06-23)

The macOS box already has ~6-8 standing multicast group memberships (IPv6 solicited-node ×2, all-nodes, mDNS v4/v6, STP/bridge management) that get handed to the driver automatically. Confirmed the hash computation against all of them matched a from-scratch Python port computed independently, including byte-for-byte agreement on the resulting filter table dump (e.g. `filter=00 c0 00 02 00 40 01 40` decoding exactly to the logged per-address bits).

Joined a real IP multicast group (`239.255.1.1` → `01:00:5e:7f:01:01`, chosen to land on bucket 18, confirmed clear of the existing occupied buckets `{14,15,25,46,48,62}`) via a Python `IP_ADD_MEMBERSHIP` socket on `en9`. Log confirmed `doSetMulticastAddresses[0]: mac=01:00:5e:7f:01:01 hashBit=18 (byte=2 bit=2)` and the filter dump gained exactly that bit. Sent a real UDP packet to that group from the Linux peer — note the first attempt sent nothing, because the sender's outgoing interface for a multicast destination is chosen by the routing table (`ip route get 239.255.1.1` showed it picked the wrong NIC, `wlp2s0`), not by which interface you "meant"; fixed by setting `IP_MULTICAST_IF` explicitly to the correct interface's address. After that fix: the Mac-side listening socket printed `Received 15 bytes from (...)` — real application-level delivery, not just visible in `tcpdump`.

### Negative control, repeated against the real table (2026-06-23)

Computed a second address (`239.255.1.2` → `01:00:5e:7f:01:02`, bucket 5) deliberately chosen to avoid every bucket occupied by the real, currently-joined group list. Sent a frame to it *without* joining that group — confirmed dropped, including against `tcpdump --no-promiscuous-mode` to rule out self-contamination. Proves the filter is discriminating by hash bit, not admitting multicast wholesale.

### AMALL fallback validation (2026-06-23)

Temporarily lowered `AQ_MAX_MCAST_ADDRESSES` to `5` in a real build (the macOS box's own standing multicast joins already exceed that, so no manual group creation needed to trigger it). Confirmed in the log: `doSetMulticastAddresses: count=7 exceeds max 5, falling back to AMALL`, and `RX_CTL` gained the `AMALL` bit (decoded `0x029a` = `IPE|START|AB|AM|AMALL`). Re-sent the *same* non-colliding negative-control address from above (`01:00:5e:7f:01:02`, hash bit 5, confirmed absent from the live filter table at the time) — now **admitted**, flipping the earlier confirmed-dropped result. This proves `AMALL` genuinely bypasses per-address filtering rather than the admission being a coincidental table match. Restored `AQ_MAX_MCAST_ADDRESSES` to `64` afterward.

### Conclusion

Multicast filtering works end-to-end across both mechanisms: per-address CRC32-hash filtering (verified against an independent reference implementation and real socket delivery, not just register writes) and the `AMALL` accept-all fallback for when the address count exceeds the hash table's capacity (verified to actually bypass per-address filtering, not just set a bit with assumed effect).

Initially, only the overflow→`AMALL` direction was tested above — the count dropping back under the threshold afterward was not, and reasoning through that direction surfaced a real bug. Reproduced, fixed, and re-validated below.

### AMALL-retraction bug: reproduced, then fixed and re-validated (2026-06-23)

Throughout this test, each negative-control address was computed independently in Python (the same CRC32/`bitrev32` algorithm the driver uses) and deliberately chosen to land on a hash bucket clear of every bucket occupied by macOS's real, currently-joined multicast groups at the time — checked freshly each round rather than assumed to still hold from an earlier round. This is what makes "admitted" or "dropped" actually mean something here: without that check, a result could just be coincidental overlap with an unrelated, legitimately-joined group's hash bit, not evidence about `AMALL` specifically.

**Reproduced (before the fix):** lowered `AQ_MAX_MCAST_ADDRESSES` to `10`. Joined 5 extra multicast groups (`239.255.2.1`-`.5`) on top of macOS's standing ~7-8, pushing `count` to `12` — confirmed the fallback engaged (`RX_CTL=0x029a`). Sent a frame to a freshly-computed non-colliding address (`239.255.3.1` → `01:00:5e:7f:03:01`, bucket 2, confirmed clear of every bucket occupied this session) and confirmed it admitted, as expected with `AMALL` active. Dropped all 5 extra groups. The driver correctly recomputed and wrote a fresh 7-entry hash table (`filter=00 c0 00 82 00 40 01 40`) — but `RX_CTL` stayed at `0x029a`, `AMALL` never cleared. Re-sent the identical `01:00:5e:7f:03:01` frame (still confirmed clear of this fresh table too): **still admitted**, despite being absent from the table and `count` well within hash-table capacity. Confirmed the bug exactly as predicted — `AMALL` had no path to retract once the overflow trigger set it.

**Fix:** see `IMPL_PLAN.md` "Bug fix plan — AMALL fallback can never be retracted once triggered by address-count overflow" for the implementation (separate `allMulticastRequested`/`mcastCountExceeded` triggers, recomputed via a shared helper).

**Re-validated (after the fix):** repeated the identical reproduction — joined the same 5 groups, `count=12`, `AMALL` engaged (`RX_CTL=0x029a`), `01:00:5e:7f:03:01` admitted as the "before" reference point. Dropped the 5 groups again: `count=7`, fresh table written, and this time `RX_CTL=0x0298` — `AMALL` correctly cleared. Re-sent the identical frame: no longer captured by `tcpdump` at all, confirming the retraction held at both the register level and actual frame-admission behavior. Restored `AQ_MAX_MCAST_ADDRESSES` to `64` afterward.

---

## VLAN Support

### Step 2 — hardware-VLAN capability experiment (2026-07-02): DTS "blocked" verdict confirmed empirically

Ran the experiment Apple DTS suggested (see `IMPL_PLAN.md` M6e, `notes/vlan_re.md`):
declare the undocumented BSD/KPI hwassist value `IF_HWASSIST_VLAN_TAGGING`
(`0x00010000`, adjacent to the published SoftwareVlan bit `0x00020000`) and see
whether anything changes. Branch `test-hardware-vlan-bit`, kept unmerged. All
runs used real rebuild/reinstall/reattach cycles and the Step 1 rig
(`tools/setup-vlan1234.sh`, continuous tagged ICMP from the remote peer).

**Baseline re-verification first.** Before introducing any variable, re-confirmed
the Step 1 result on current `main`: bidirectional `802.1Q vlan 1234` ICMP on
the parent capture, 100% replies.

**`SetSoftwareVlanSupport(true)` removed from `Start()` (`aee26cf`) and proven
inert by A/B/A.** The 2026-06-20 session had established the call does nothing,
but the removal never actually landed. Removed it (also eliminating a potential
confound for the bit experiment: "software VLAN explicitly requested" preempting
hardware capability consideration had never been ruled out), re-ran the full
bench: identical pass. A checksum difference in the captures briefly looked like
a counter-example — with the call removed, outgoing replies left the local `en9`
tap with IP checksum `0000` (deferred to TX checksum offload) where the previous
run showed a software-computed value. Re-adding the call (A/B/A) still produced
`0000`, so the call is not causal; the offload-propagation difference is rig
state (likely whether `vlan0` was freshly recreated relative to driver attach),
not driver code. Two useful byproducts: capture checksum fields are not a valid
signal for comparing driver builds, and the remote-side capture (valid checksum
arriving, 100% replies, local pre-hardware tap showing `0000`) proves the AQC111
TX checksum engine correctly inserts the IP header checksum through an inline
802.1Q tag.

**The experiment itself** — `0x00010000` declared via `getFeatureFlags()` +
hwAssist self-init, plus both `setHardwareAssists` generations implemented with
logging (deprecated NDK_21 `SetHardwareAssists` and mask-based NDK_22
`setHardwareAssists`) so any OS-side write would be visible:

| Signal | A: bit + SoftwareVlan | B: bit alone |
|---|---|---|
| `GetHardwareAssists` readback | `0x20030007` (bit retained) | `0x20010007` (bit retained) |
| `getVlanTag()` on outbound `vlan(4)` traffic | `has=0`, tag inline | `has=0`, tag inline |
| RX frames | tag inline (software demux) | tag inline (software demux) |
| Either `setHardwareAssists` called by OS | never | never |
| `vlan0` MTU | — | **1496 (clamped)** |

**Conclusion:** the undocumented value is ignored wholesale, not partially
honored — in permutation B it doesn't even receive the VLAN-MTU accounting the
published SoftwareVlan bit provides (`mtu 1496` vs `1500`). And nothing is
observably "stripped in a setter", because the OS never calls either setter
generation at all. Hardware VLAN offload is unreachable from the public SDK,
now on empirical rather than DTS-asserted footing. Filed as `FB23530504`
(SDK docs reference the nonexistent `kFeatureHardwareVlan`); companion
Suggestion drafted in `notes/fb2_hardware_vlan_er.md`.

### Step 1 — Layer 1 fix (2026-06-20): software VLAN path validated end-to-end

Implemented the fix predicted but not yet built when Step 0 found the bug:
called `SetSoftwareVlanSupport(true)` in `Start()` (a concrete `IOUserNetworkEthernet`
base-class method the driver calls, not one it overrides — the original plan
had this backwards), added `kIOUserNetworkHWAssistSoftwareVlan` to the
declared/self-enabled hwAssist mask, and added a 4-byte allowance
(`AQC111_VLAN_TAG_LEN`) to the TX/RX frame-size checks and buffer sizing.

A second bug then appeared on the RX/software-demux side: `hwOnLinkUp()` had
inherited the original x86 kext's `SFR_VLAN_ID_CONTROL` write of `0x10`
(`SFR_VLAN_CONTROL_VSO`, VLAN strip on). That is wrong for this layer-1
software VLAN pass. It removes the inline 802.1Q header before macOS `vlan(4)`
can classify the packet, while this driver does not yet forward hardware RX
descriptor VLAN metadata to Skywalk. The fix is to write `0x00` to
`SFR_VLAN_ID_CONTROL` on link-up, preserving inline tags for software demux.

**Initial TX tagging confirmation, multiple independent ways:**
- `vlan0`'s MTU corrected from `1496` (BSD's "parent doesn't support
  VLAN_MTU" clamp) to `1500`, matching the Apple CDC/ECM reference exactly.
- The byte-level 802.1Q tag (`81 00 04 d2`) now genuinely appears inline in
  the buffer this driver's `txDrainOne()` receives — confirmed via added
  diagnostic logging (`getVlanTag()` + raw byte dump). Before this fix, the
  same diagnostic showed a plain, untagged 98-byte buffer.
- Remote-side capture confirmed actual wire-level tagged frames arriving
  (`802.1Q, vlan 1234`, correct TPID), for both DHCP broadcast traffic and
  ICMP echo requests, across multiple independent test runs.
- Once a stale `rx-vlan-offload` setting on the remote's NIC was disabled
  (`ethtool -K <if> rxvlan off` — a Realtek/`r8152` driver quirk, unrelated
  to this project), the remote's `vlan1234` sub-interface RX counter
  incremented and `tcpdump -i vlan1234` showed the frame correctly
  demuxed/decapsulated. This is the first real confirmation that an inbound
  tagged frame is handled correctly end-to-end at the remote.

**Final clean test rig:** moved away from link-local `/16` addressing and gave
the parent no IPv4 address, leaving only `vlan0` with `172.16.123.20/24` on
VLAN tag `1234`; the remote peer was `172.16.123.10/24`. This removes the
earlier route/ARP ambiguity between `en9` and `vlan0`. The reproducible local
setup is `tools/setup-vlan1234.sh`.

**Positive control, parent view (`en9`):** after disabling hardware VLAN
stripping, `tcpdump -n -XX -e -i en9` showed both directions with inline
802.1Q headers on the parent:

```text
3c:8c:f8:f9:d7:a3 > 58:ef:68:e2:8e:95, ethertype 802.1Q (0x8100), length 102: vlan 1234, p 0, ethertype IPv4 (0x0800), 172.16.123.20 > 172.16.123.10: ICMP echo request
58:ef:68:e2:8e:95 > 3c:8c:f8:f9:d7:a3, ethertype 802.1Q (0x8100), length 102: vlan 1234, p 0, ethertype IPv4 (0x0800), 172.16.123.10 > 172.16.123.20: ICMP echo reply
```

The outbound request's IPv4 header checksum is still visible as `0000` in the
local capture. That is expected with TX checksum offload at this vantage point;
the inbound reply carries a completed checksum.

**Positive control, VLAN view (`vlan0`):** `tcpdump -n -XX -e -i vlan0` showed
both directions decapsulated as normal IPv4 Ethernet frames:

```text
3c:8c:f8:f9:d7:a3 > 58:ef:68:e2:8e:95, ethertype IPv4 (0x0800), length 98: 172.16.123.20 > 172.16.123.10: ICMP echo request
58:ef:68:e2:8e:95 > 3c:8c:f8:f9:d7:a3, ethertype IPv4 (0x0800), length 98: 172.16.123.10 > 172.16.123.20: ICMP echo reply
```

This proves the parent receives tagged frames intact and macOS `vlan(4)`
delivers only the matching VLAN traffic to `vlan0`.

**Negative control, mismatched VLAN ID:** the remote then sent the same traffic
on VLAN tag `1235` while the local `vlan0` remained configured for tag `1234`.
The parent saw the frame:

```text
58:ef:68:e2:8e:95 > 3c:8c:f8:f9:d7:a3, ethertype 802.1Q (0x8100), length 102: vlan 1235, p 0, ethertype IPv4 (0x0800), 172.16.123.10 > 172.16.123.20: ICMP echo request
```

`vlan0` did not receive those `1235` frames; the only traffic visible there was
local ARP from `172.16.123.20` looking for `172.16.123.10` on VLAN `1234`.
That is the expected negative result and proves the fix did not flatten all
tagged parent traffic into `vlan0`.

**Conclusion:** M6e Layer 1 software VLAN support is validated. Required pieces
are declaring `kIOUserNetworkHWAssistSoftwareVlan`, allowing `+4` bytes in
TX/RX frame-size checks and buffers, and disabling hardware VLAN stripping
(`SFR_VLAN_ID_CONTROL=0x00`) until a future hardware VLAN metadata path exists.
(`SetSoftwareVlanSupport(true)` was originally listed as a required piece here,
but later testing proved it inert and it was removed from `Start()` — see
Step 2.) Hardware tag insert/strip remains out of scope for this pass.

### Step 0 — baseline test (2026-06-20): confirmed broken before any code changes

Per `IMPL_PLAN.md` M6e's plan, tested whether software VLAN tagging (`vlan(4)`)
already works against the *unmodified* driver before writing any code.

**Methodology**: built `tools/baseline-vlan0.sh`, a deterministic, idempotent
test harness (parameterized via env vars, logs every command + exit status)
that sets up a `vlan0` pseudo-interface on tag `1234` over `en9`, with
distinct addresses for the parent (`169.254.245.127/16`) and VLAN
(`169.254.113.129/16`) interfaces, a scoped host route + ARP entry for the
remote peer pinned to `vlan0` specifically (necessary — without this, macOS
can cache the peer's MAC on `en0` instead and `ping -b vlan0` fails with "no
route to host", which would look like a driver bug but isn't one).

**Reference baseline (Apple CDC/ECM, not DriverKit)**: ran the harness
against the same adapter bound via macOS's built-in CDC fallback driver
instead of this project's DriverKit driver. Result: `vlan0` produced
remote-visible `802.1Q` tag `1234` traffic, 0% packet loss over 4 pings.
This establishes that the adapter, peer, VLAN ID, route, and ARP setup are
all valid — any failure against the DriverKit driver can't be blamed on the
test method itself.

**DriverKit result**: re-ran the identical harness against this project's
(unmodified) driver. Local `tcpdump -eni en9` decodes the outbound ICMP as
correctly VLAN-tagged:

```text
3c:8c:f8:f9:d7:a3 > 1c:86:0b:3b:e7:f6, ethertype 802.1Q (0x8100), length 102: vlan 1234, p 0, ethertype IPv4 (0x0800), 169.254.113.129 > 169.254.50.51: ICMP echo request
```

But **the remote end received no frames at all** for this traffic. Reverting
to the CDC driver with the identical setup immediately restored working,
remote-visible VLAN traffic. This is the same "local capture isn't
authoritative" lesson from TX checksum offload testing, now confirming an
actual bug rather than just a methodology gap: something in the DriverKit
TX path silently drops or mangles VLAN-tagged (4-byte-oversized) frames
before they leave the device, despite the local buffer/capture looking
superficially correct.

**Ruled out as a separate issue**: the local packet hex shows IP header
checksum `0000` at this capture point — this is the expected TX-checksum-
offload placeholder behavior already validated in M6b (driver hands a
zero checksum to hardware, which is supposed to fill it in before
transmission), not evidence of a second, unrelated bug. Worth stating
explicitly since it would be easy to misread as "two things are broken"
when only VLAN handling actually is.

**Conclusion**: VLAN support is not "not implemented yet," it's actively
broken in the DriverKit TX path for any VLAN-tagged frame, even via the
software-only `vlan(4)` accommodation path that's supposed to need zero
driver code changes. Next step is `IMPL_PLAN.md` M6e's Layer 1
implementation, instrumented to find out exactly what happens to the extra
4 bytes between submission and the wire, rather than assuming the
predicted size-check rejection is the root cause without checking.

Raw logs: `notes/setup-vlan0.log`, `notes/baseline-vlan0.log`,
`notes/diag-vlan0.log`. Full narrative: `notes/cdc-vlan-baseline-2026-06-20.md`.

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

## TSO (TCP Segmentation Offload) — M10

Full transcripts: `notes/tso_validation_gro.md` (wire segmentation + GRO trap)
and `notes/tso_sha256_validation.md` (integrity + lossy run). Branch
`tso-offload`, 2026-07-03.

### Methodology

Sender: this driver (`en9`, 172.18.0.20). Receiver: Linux peer
(172.18.0.10), TCP port 5001, bulk transfers via `nc`. Engagement observed
via `txDrainOne` Debug logs (`getTSOInfo` segsz/flags plus `dataLen` ≫ MTU);
wire shape observed via `tcpdump` on the peer; integrity via SHA-256 of
1 GiB random transfers.

### Engagement (2026-07-03)

With `kIOUserNetworkHWAssistTSO4/6` advertised and `getTSOOptions` reporting
65535, the stack handed super-packets immediately: `TSO segsz=1448
flags=0x100000 len=5858` (= 66 header bytes + exactly 4×1448 payload).
Descriptor verified: `desc=000005a8000016e2` — MSS 1448 in bits 46:32,
length 5858 in bits 20:0. Negative baseline: all TX logging prior to
advertising the capability had never shown a super-MTU packet.

### False negative: the Linux GRO capture trap (2026-07-03)

The peer's `tcpdump` initially showed the transfer arriving as single
5858-byte packets — indistinguishable from the device ignoring the MSS field
and emitting jumbo frames. Two real-but-irrelevant fixes were made while
chasing this (Linux-parity 8-byte TX padding + `DROP_PADD`, and BM/ARC
link-up zeroing — the latter's readback probe showed the registers were
already zero). The actual cause was **receiver-side software GRO**: the Linux
kernel re-coalesces consecutive TCP segments before tcpdump's tap point.
Proved by A/B: `ethtool -K <if> gro off` → same test captured normal
1514-byte frames with 1448-byte payloads matching the descriptor MSS;
`gro on` → the 5858-byte "jumbo" reappeared instantly. The hardware had been
segmenting correctly the whole time.

### Positive validation — integrity (2026-07-03)

1 GiB of `/dev/urandom` sent through the TSO path: SHA-256 identical on both
ends (`8b257a43…b0fe`), 414 MB/s (~3.3 Gbps) single-stream `nc`.

### Positive validation — recovery under loss (2026-07-03)

Second 1 GiB run with 0.5% induced ingress loss on the peer (IFB + netem;
1,329 packets dropped). macOS sender counters: +3,593 retransmitted segments
(all via RACK), +11,448 dup-acks, +12,982 SACK blocks. SHA-256 still matched.
This exercises the segmenter on retransmit-boundary segment sizes, not just
clean full-window bursts. Note: read retransmission counters on the *sender*;
the receiver only observes its own induced drops.

### Positive validation — TSO6/IPv6 (2026-07-03)

Same bench pair on `fd00:111::/64`, peer GRO off. Engagement:
`TSO segsz=1428 flags=0x200000 len=5798` — MSS correctly 20 bytes smaller
than the v4 case (40-byte IPv6 header), descriptor
`desc=00000594000016a6` (MSS 0x594=1428, len 0x16a6=5798), `usb_len=5808`
showing the 8-byte descriptor + alignment padding. Wire: 1514-byte
`ethertype IPv6` frames with 1428-byte TCP payloads
(14 eth + 40 IPv6 + 32 TCP/opts + 1428 = 1514). 1 GiB SHA-256 matched.

### Positive validation — TSO4 × software VLAN (2026-07-03)

VLAN rig (`vlan0`/`en9` ↔ Linux `vlan1234`, VID 1234, 172.16.123.0/24).
The stack hands VLAN-tagged TSO super-packets with the 802.1Q header INLINE
in the frame template (`getVlanTag has=0` — no metadata path), e.g.
`desc=000005a8000016e6` for an 18-byte L2 header + 5844-byte IPv4 packet
= 4×1448 payload. The segmenter parsed past the inline tag and emitted
1518-byte VLAN-tagged wire frames with correct checksums (verified by
tcpdump `cksum ... (correct)` on the peer). 1 GiB SHA-256 matched.
This confirms the replicate-and-patch model: the tag is just template bytes.

### Conclusion

TSO4, TSO6, and TSO4-over-software-VLAN are functionally correct:
engagement, descriptor encoding, hardware segmentation on the wire (tagged
and untagged), sustained integrity, and recovery under loss are all
validated. Deferred TODOs, not M10 gates: strict per-burst pcap invariants
(IP ID/seq/flags script — the clean/lossy/VLAN/v6 SHA-256 runs cover
correctness in aggregate) and the iperf3+CPU comparison (general
performance/benchmarking work item).

---

## Wake-on-LAN (magic packet) — M11 phase 1

### Baseline (2026-07-05, pre-arming build): wake path provably absent

`pmset -a womp 1` probed `GetHardwareAssists` only; `SetWakeOnMagicPacketEnable`
was never called. Peer-side polling + `pmset -g log` correlation showed the
link dies ~1s after every genuine "Entering Sleep state" (hwDisable withdraws
advertise + lowPower). Earlier "PHY stayed up during sleep" observations were
disambiguated as TCPKeepAlive DarkWakes: every remote link transition mapped
1:1 to pm-log Sleep/DarkWake edges (e.g. 02:31:23 sleep → +4s peer sees link
dying, 02:31:24 DarkWake → +9s peer back at 1G, 02:32:08 maintenance sleep →
02:32:10 peer link down). With the link down, a magic packet is undeliverable —
baseline wake path does not exist.

### The latch problem: OS never calls SetWakeOnMagicPacketEnable

Zero calls observed across womp toggles, sleep entries, and deep-idle
transitions over many cycles — despite `SetWakeOnMagicPacketSupport(true)`
accepted in Start, WOMP (0x04000000) in both `getFeatureFlags` and the
`GetHardwareAssists` readback (0x24620007), and IOPMrootDomain listing
WakeOnMagicPacket providers. The arming code below the latch is only
reachable by forcing the latch (temporary bench build) — production latch
policy TBD; likely Feedback Assistant material.

### Positive validation (2026-07-05, forced-latch build): end-to-end wake proven

- **Arming:** both transfers (290-byte WOL_CFG via 0x60; phy_cfg =
  advertise|AQ_WOL = 0x033b000f via 0x61) returned 0x0 at every
  `SetPowerState(Off)`, including the second Off pass at the deep-idle
  transition — every DarkWake cycle re-arms automatically.
- **Link persistence:** armed PHY held 1G through a continuous 190-second
  Deep Idle sleep with zero DarkWakes (baseline: dead in ~1s).
- **Wake:** peer `sudo etherwake -i <if> <our MAC>` every 10s → ~25
  consecutive sleep entries each terminated 5-15s later by
  `DarkWake from Deep Idle due to ATC2.USBWakeup`.
- **Dose-response:** interval changed to 20s → wakes grid-locked to
  :03/:23/:43 to the second; machine slept undisturbed through ambient
  traffic between grid points (implicit negative control: firmware MP filter
  ignores non-magic frames). Reproduced on AC and battery.
- **USB precondition:** Config 1 `bmAttributes=0xa0` (remote wakeup
  supported; Config 2 is 0x80 — not). ATC2 wakes prove the host arms the
  port without driver involvement.

### Key insight: macOS network wakes are DarkWakes by design

The screen never turns on for a WoL wake — the machine comes up dark and
network-reachable (Wake-on-Demand semantics); only HID activity promotes to
FullWake. "It never woke" while `pmset -g log` shows ATC2.USBWakeup DarkWakes
IS the success condition. Attribute wakes by reason string
(`ATC2.USBWakeup` = our USB port, `wifibt` = WLAN/BT maintenance,
`trackpadkeyboard` = user).

### Negative control (2026-07-05): PASSED on the unwired build

Forced latch reverted; same bench + etherwake cadence. Peer confirmed link
down throughout. `pmset -g log`: one continuous 584-second Deep Idle sleep
(06:11:24), zero ATC2.USBWakeup, zero DarkWakes of any kind, terminated only
by user HID at 06:21:08. The identical packet stream that produced ~35 wakes
when armed produced none unarmed — causation closed in both directions.
Optional gold-standard remains: wrong-MAC etherwake against a re-armed build.

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
- **Linux receivers lie to tcpdump about packet sizes** — software GRO
  coalesces consecutive TCP segments *before* the capture tap, so correct
  sender-side TSO looks like oversized/jumbo wire frames. Disable
  `gro` (and `rx-gro-hw`) via ethtool on the capture host before
  interpreting packet lengths in any wire-level TX validation. Caught as a
  false negative during M10 TSO bring-up: two speculative driver fixes were
  made before an ethtool A/B proved the frames were fine.
- **Dext log lines emitted in the first moments of wake are silently and
  consistently lost** — during M11 PM instrumentation, SetPowerState(On)
  fired on 5/5 wakes (proven by cumulative counters read out from later,
  reliable log points) while 0/5 of its log lines survived to capture; the
  `SetInterfaceEnable: 1` entry line was likewise lost on every wake. A
  wake-path event that "never logs" has NOT been shown to never happen.
  Durable technique: bump a counter in the suspect callback and print it
  from a later reliably-captured line (e.g. link-up) — cumulative counts
  survive any log-loss window.

- **Peer-observed link state cannot distinguish armed-sleep, DarkWake, and
  awake** (2026-07-05, M11): "the PHY stayed up during sleep" may be a
  TCPKeepAlive DarkWake that re-enabled the interface. Always correlate
  remote observations against `pmset -g log` edges (Entering Sleep /
  DarkWake / Wake + reason string) before attributing link behavior to
  arming or hardware. Wake attribution: reason `ATC2.USBWakeup` = USB
  remote wake from our port; network wakes are DarkWakes by design (screen
  off ≠ no wake).

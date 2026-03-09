# AQC111 DriverKit Implementation Plan

## Architecture

Single dext, Option A: `AQC111` inherits `IOUserNetworkEthernet` (which inherits `IOService`).
Matches at device level (`IOProviderClass=IOUSBHostDevice`). `Start()` opens the device,
sets Config 1, finds and opens the vendor interface and its 3 pipes, inits hardware, then
registers the network interface. No second personality or second dext needed.

### File structure

```
AQC111/AQC111/
  AQC111.iig          driver class declaration (IOUserNetworkEthernet)
  AQC111.cpp          Start/Stop/enable/disable/txPacketsAvailable
  AQC111Hal.cpp       plain C++ helpers: vendorRead/Write, hwInit, hwStart, hwStop, PHY ops
  AQC111Rx.cpp        RX ring: bulk IN URB pool, completion parsing, packet delivery
  AQC111Tx.cpp        TX ring: txPacketsAvailable loop, descriptor prepend, URB submit
```

### Endpoints (Config 1, vendor interface class=255)

| EP  | Direction | Type      | Size  | Role           |
|-----|-----------|-----------|-------|----------------|
| EP1 | IN        | Interrupt | 16B   | Link status    |
| EP2 | IN        | Bulk      | 1024B | RX data        |
| EP3 | OUT       | Bulk      | 1024B | TX data        |

---

## Milestones

### M1 — Pipes open

**Goal:** USB layer works end-to-end; no data path yet.

Tasks:
- Change base class to `IOUserNetworkEthernet` in `.iig` and build settings
- After `SetConfiguration(1, true)`, call `CopyInterface()` to obtain the vendor interface
- Open vendor interface, open EP1/EP2/EP3 pipes
- Log endpoint addresses and pipe open results

**Pass signal:** dext loads cleanly, logs show 3 pipes opened, device does not re-enumerate.

---

### M2 — HW init + MAC address

**Goal:** MAC SFRs configured, correct MAC address visible in `ifconfig`.

Tasks:
- Implement `vendorRead` / `vendorWrite` wrappers (bRequest=`AQ_ACCESS_MAC`)
- Read firmware version (SFR 0xDA–0xDC) and log as sanity check
- Run full MAC SFR init sequence from RE (SFR_MEDIUM_STATUS_MODE, SFR_BM_INT_MASK,
  SFR_RXCOE_CTL, SFR_TXCOE_CTL, SFR_BULK_OUT_CTRL, etc.)
- Read MAC address from SFR_NODE_ID (6 bytes at SFR 0x10), implement `getHardwareAddress()`
- Register the network interface

**Pass signal:** `ifconfig` shows `en` interface with MAC matching the label on the adapter.

---

### M3 — Link up via interrupt

**Goal:** Interface goes active at correct speed after cable plug-in.

Tasks:
- Post a single URB to EP1 (interrupt IN, 16B buffer)
- In completion handler: parse ItrData (AQ_LS_MASK=0x8000, AQ_SPEED_MASK=0x7F00>>8),
  map speed code to IONetworkMedium, call `setLinkStatus()`
- Re-post interrupt URB after each completion (perpetual re-arm)
- Send initial `AQ_PHY_OPS` (bRequest=0x61) with MediumFlags advertising all speeds
  (bits 0–3 set) and PHY_POWER_EN (bit 20)

**Pass signal:** `ifconfig en0` shows `status: active` at 5000baseT; link light on adapter.

---

### M4 — RX (receive only)

**Goal:** Incoming packets visible in tcpdump; no TX yet.

Tasks:
- Pre-post N bulk IN URBs to EP2 (ring of ~10 slots, 16KB each as per RE)
- In completion: parse 4-byte descriptor header (pkt_count = bits 12:0, desc_offset = bits 31:13 << 13)
- Walk per-packet 8-byte descriptors at desc_offset; for each: check RX_OK (bit 11), DROP (bit 31),
  extract pkt_len (bits 30:16), skip AQ_RX_HW_PAD=2 bytes, hand payload to `IOUserNetworkPacket`
- Apply RX coalescing config to SFR_RX_BULKIN_QCTRL (profile selected by link speed)
- Assign static IP to interface for testing (`ifconfig en0 192.168.x.x`)

**Pass signal:** from another machine, `ping <static IP>` — packets visible in
`tcpdump -i en0` even though pings don't complete (no TX yet).

---

### M5 — TX (full duplex)

**Goal:** Round-trip ping works.

Tasks:
- Implement `txPacketsAvailable()`: dequeue `IOUserNetworkPacket`, prepend 8-byte TX descriptor
  header (bits 20:0 = length, bit 28 = drop-padding), submit to EP3
- In TX completion: release packet buffer, signal queue ready for more
- Handle back-pressure (stall queue when all TX slots in flight; unstall in onComplete)

**Pass signal:** `ping` round-trips from the Mac. Full duplex confirmed.

---

### M6 — Correctness + offload

**Goal:** DHCP works, checksum offload active, ready for performance testing.

Tasks:
- Enable RX checksum offload: write SFR_RXCOE_CTL (IP/TCP/UDP/TCPv6/UDPv6 bits)
- Enable TX checksum offload: write SFR_TXCOE_CTL
- Implement `getChecksumSupport()` returning `0x67` for `kChecksumFamilyInet`
- Implement `Rx::setChecksumResult()`: decode L3/L4 type + error bits from RX_PD,
  call `setChecksumResult(mbuf, kChecksumFamilyInet, checked, valid, 0, 0)`
- Implement multicast hash filter (SFR_MULTI_FILTER_ARRY) and promiscuous mode
- DHCP: `ipconfig set en0 DHCP`

**Pass signal:** DHCP address acquired; `iperf3` to a local host shows throughput in the
expected range for a 5G link.

---

## Known Risk Points

| Area | Risk | Mitigation |
|------|------|-----------|
| M2: HW init order | MAC SFR sequence is long and order-sensitive; wrong order = no link | Follow hwStart sequence from RE_LOG.md exactly |
| M3: PHY ops | MediumFlags 32-bit payload must be correct; wrong bits = PHY won't advertise | Cross-check with RE MediumFlags bit table |
| M4: RX buffer parsing | pkt_count / desc_offset layout is fiddly; off-by-one = crashes or garbage | Start with N=1 URB, log raw descriptor bytes before parsing |
| M4: IOUserNetworkPacket API | DriverKit packet API differs from mbuf; buffer ownership rules differ | Check NetworkingDriverKit sample for correct acquire/complete lifecycle |
| General | dext state gets tangled between test runs | `systemextensionsctl uninstall` + reboot if multiple entries appear |

## Notes

- ICMP checksum offload: hardware supports it (SFR_RXCOE_CTL bits 3,7) but not worth implementing — skip.
- IOUserNetworkEthernet requires `com.apple.developer.networking.driverkit` entitlement in addition to the USB entitlement.
- TX descriptor MSS field (bits 46:32) and VLAN fields: leave zero for now (no TSO or VLAN tagging needed initially).
- RX VLAN (bit 10 of RX_PD): skip for M4/M5; can be wired up in M6 polish if needed.

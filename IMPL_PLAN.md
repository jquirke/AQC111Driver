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
- RX checksum offload: enable `SFR_RXCOE_CTL`; decode L3/L4 result bits from RX descriptor
- TX checksum offload: enable `SFR_TXCOE_CTL`; advertise checksum capability to stack
- Multicast hash filter (`SFR_MULTI_FILTER_ARRY`) and promiscuous mode

**Pass signal:** DHCP address acquired; `iperf3` shows throughput in expected range for 1G/5G link.

### M7 — Advanced hardware features (planned, post-stability)

- TSO (TX descriptor MSS field, bits 46:32)
- Jumbo frames (MTU > 1500; hardware supports ~16 KB)
- VLAN offload (RX descriptor bit 10; `SFR_VLAN_ID_CONTROL`)
- Wake-on-LAN

---

## Known Risk Points

| Area | Risk | Mitigation |
|------|------|-----------|
| M6: RX CTL cycling | hwOnLinkUp must stop then restart RX precisely; wrong order = no RX | Mirror Linux `aqc111_rx_fixup` / link-up sequence exactly |
| M6: DHCP | Requires correct ARP handling (already working) + IP stack integration | Should work once static-IP ping is solid |
| General | Corpse budget (~2 unplug cycles/boot) exhausts quickly | Plan test runs to minimize unplugs; reboot to reset |

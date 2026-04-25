# AQC111 DriverKit — Notes

DriverKit system extension for AQC111-based USB 5Gbps Ethernet adapters on Apple Silicon macOS.

## Background

- Manufacturer (AQTION) does not support Apple Silicon; product discontinued
- Device exposes **2 USB configurations**:
  - **Config 1** (`iConfiguration: "LAN"`) — proprietary vendor-specific interface (class 255). High performance.
  - **Config 2** — CDC Ethernet (class 10). macOS binds this by default; poor performance.
- Goal: DriverKit extension that claims Config 1, enabling full 5Gbps throughput.

## Device

- VID: `0x20f4`, PID: `0xe05a` (TRENDnet TUC-ET5G)
- Firmware version: 130.5.32 (major=0x82 ≥ 0x80 → FWPhyAccess, not DirectPhyAccess)
- Config 1 endpoints:
  - EP1 IN — Interrupt, 16 bytes (link status)
  - EP2 IN — Bulk, 1024 bytes (RX)
  - EP3 OUT — Bulk, 1024 bytes (TX)

## Current Status

**All core data-path milestones complete as of 2026-04-25.**

- USB enumeration with Config 1 forced ✓
- Ethernet interface registered (`en10`, MAC read from hardware) ✓
- PHY bring-up, 1000baseT full-duplex ✓
- `ifconfig enX up` / `ifconfig enX down` ✓
- End-to-end RX: frames in Wireshark/tcpdump ✓
- End-to-end TX: ARP resolves, `ping` succeeds ✓

## Architecture

Two DriverKit personalities in a single dext bundle. See README.md for a full description.

### Personality A — AQC111 (`IOUserService`)
- Matches `IOUSBHostDevice` (VID/PID)
- Calls `SetConfiguration(1, matchInterfaces: true)`, holds USB session open to pin Config 1

### Personality B — AQC111NIC (`IOUserNetworkEthernet`)
- Matches `IOUSBHostInterface` (Config 1, `bInterfaceClass=255`)
- Uses `CopyDevice()` for control transfers; Personality A holds the exclusive session
- Bulk RX/TX + interrupt pipe; registers Skywalk Ethernet interface

## Wire Formats

### RX (USB Bulk IN, EP2)

Aggregate buffer layout (hardware delivers multiple frames per USB transfer):

```
[4-byte aggregate header]
  bits 12:0  = pkt_count
  bits 31:13 = desc_offset >> 3  (byte offset to per-packet descriptor array)

[per-packet 8-byte descriptors at desc_offset]
  bit  31    = DROP
  bit  11    = RX_OK
  bits 30:16 = pkt_len (includes AQ_RX_HW_PAD=2 skip bytes)
  ...

[frame data: skip 2-byte AQ_RX_HW_PAD, then raw Ethernet frame]
```

### TX (USB Bulk OUT, EP3)

8-byte LE descriptor prepended to each Ethernet frame:

```
bits 20:0 = frame_len  (all other bits 0)
```

Total USB transfer = 8 + frame_len bytes.

### Interrupt (EP1, 16 bytes — ItrData)

```
byte[0:1] LE 16-bit:
  bit15      = link up
  bits 14:8  = speed code
byte[2] bits[1:0] = active flow control
```

Speed codes: `0x0F`=5G, `0x10`=2.5G, `0x11`=1G, `0x13`=100M

## Hardware Register Access

- **bRequest=0x01** (`AQ_ACCESS_MAC`): OUT (0x40) = write; IN (0xC0) = read. `wValue`=register, `wIndex=wLength`=byte count.
- **bRequest=0x20** (`AQ_FLASH_PARAMETERS`): read MAC (6 bytes)
- **bRequest=0x61** (`AQ_PHY_OPS`): FWPhyAccess 4-byte control struct (firmware ≥ 0x80)

### Key SFR Registers

| Address | Name | Notes |
|---------|------|-------|
| `0x000B` | SFR_RX_CTL | `0x0000`=stop, `0x0288`=START\|IPE\|AB |
| `0x0010` | SFR_NODE_ID | 6-byte MAC address |
| `0x0022` | SFR_MEDIUM_STATUS_MODE | For 1G: write `0x0032`, then `0x0132` |
| `0x002E`–`0x0032` | SFR_RX_BULKIN_QCTRL | 5-byte RX coalescing; high-speed: `{0x07,0x00,0x01,0x1E,0xFF}` |
| `0x0041` | SFR_BM_INT_MASK | `0xFF`=unmask all |
| `0x0043` | SFR_BMRX_DMA_CONTROL | `0x80`=enable |
| `0x00B7` | SFR_ETH_MAC_PATH | `0x01`=RX_PATH_READY |
| `0x00B9` | SFR_BULK_OUT_CTRL | `0x02`=EFF_EN |

## Known Operational Issues

1. **Media re-seat required for RX flow.** After `ifconfig enX up`, no RX frames arrive until the cable is unplugged and replugged. `hwOnLinkUp` should cycle `SFR_RX_CTL` (stop then restart) as the Linux driver does on every link-up event.

2. **USB re-enumeration flap on connect.** 1–2 re-enumeration cycles on plug-in before stabilising; firmware boot behaviour.

3. **Teardown instability / reboot required.** DriverKit corpse budget exhausts after ~2 unplug cycles per boot. `Stop()` correctly aborts and closes pipes but the budget is a platform limit.

## Pending Work

1. Fix media re-seat: cycle `SFR_RX_CTL` in `hwOnLinkUp`
2. DHCP / automatic IP address assignment
3. Investigate teardown stability improvements

## Key Design Lessons

**OSAction callbacks require IIG factory methods.** Raw `OSAction::Create()` produces `OSTypeID(OSAction)`, but the IIG-generated `_Dispatch` switch gates every callback on a typed subclass ID. Type mismatch = silent, complete drop. Always use `CreateActionOnMethodName()`.

**Never replace the "Default" dispatch queue.** The networking framework installs a kernel proxy at "Default" in `Start_Impl`. `Stop_Impl` cancels this queue internally; its async completion dereferences `+0x10` on the proxy's backing object. Replacing "Default" with a plain queue nulls that pointer → EXC_BAD_ACCESS at `Stop_Impl+144`.

**`IOProviderClass` must be `IOUSBHostInterface` for the NIC personality.** Matching on `IOUSBHostDevice` lets `Start()` succeed and direct calls work, but async IO completions are routed through the interface node — a driver matched on the device is outside that delivery path.

**`SetConfiguration(1, matchInterfaces: true)` publishes interface nubs while holding the device open.** Closing the device before calling this is not required (and loses exclusive ownership).

## Prior Art / References

- Linux kernel driver: `drivers/net/usb/aqc111.c`
- Old macOS x86 kext: `~/trendiokit/` (bundle ID `com.aquantia.driver.usb.pacific`, v1.4.4)
- Apple sample: `~/Downloads/ConnectingANetworkDriver/`

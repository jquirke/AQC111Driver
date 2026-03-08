# AQC111 DriverKit — Notes & Plan

DriverKit system extension for AQC111-based USB 5Gbps Ethernet adapters on Apple Silicon macOS.

## Background

- Manufacturer (AQTION) does not support Apple Silicon and the product is discontinued
- Device exposes **2 USB configurations**:
  - **Config 1** (`iConfiguration: "LAN"`) — proprietary vendor-specific interface (class 255). High performance.
  - **Config 2** — CDC Ethernet (class 10). macOS binds this by default, performance is poor.
- Goal: DriverKit extension that claims Config 1 before the Apple CDC driver does, enabling full 5Gbps throughput.

## Device

- VID: `0x20f4`, PID: `0xe05a`
- Negotiates SuperSpeed (5Gbps) ✓
- Config 1 endpoints:
  - EP1 IN — Interrupt, 16 bytes (status/notifications)
  - EP2 IN — Bulk, 1024 bytes (RX)
  - EP3 OUT — Bulk, 1024 bytes (TX)

## Prior Art

- Linux kernel driver: `aqc111` (open source, good reference for init sequence and register protocol)
- Old macOS kext for x86 (disassembled) — reference for init sequence on macOS
- Previous DriverKit skeleton on GitHub (to be located and reviewed)

## Architecture

### Matching Strategy

**Must match at device level (`IOUSBHostDevice`), not interface level (`IOUSBHostInterface`).**

Matching at interface level arrives after macOS has already selected a configuration — by then the Apple CDC driver has claimed Config 2. Matching at device level by VID/PID intercepts the device before any configuration is selected. `Start()` then calls `SelectConfiguration(1)` to activate the proprietary config, preventing the CDC driver from ever seeing a CDC interface.

IOKitPersonalities key fields:
```
IOProviderClass: IOUSBHostDevice
idVendor: 0x20f4
idProduct: 0xe05a
```

### Driver Families

- `USBDriverKit` — for USB device/interface management
- `NetworkingDriverKit` — for exposing the NIC to the macOS networking stack

### High-Level Flow

1. Match `IOUSBHostDevice` by VID/PID
2. `Start()` — select Configuration 1
3. Open bulk IN/OUT pipes and interrupt pipe
4. Run AQC111 init sequence (firmware load if needed, register config)
5. Register with `IOUserNetworkingFamily` / `IOEthernetController`
6. RX loop: read bulk IN, pass frames to networking stack
7. TX path: receive frames from stack, write to bulk OUT
8. Handle interrupt EP for link status changes

## Development Setup

- **Local dev (pre-entitlement approval)**: SIP disabled (Permissive Security in recoveryOS), Xcode signing set to "Sign to Run Locally", `systemextensionsctl developer on`
- **Entitlements**: Apple Developer account entitlements pending review. Development does not require approval — SIP disabled is sufficient for local testing.
- **Target**: Apple Silicon Mac, macOS Sequoia

## TODO

- [ ] Locate and review existing DriverKit skeleton on GitHub
- [ ] Verify device-level matching prevents CDC driver from claiming the device
- [ ] Implement AQC111 init sequence (reference: Linux `aqc111` driver + disassembled x86 kext)
- [ ] Implement RX/TX bulk transfer loop
- [ ] Implement interrupt EP handler for link status
- [ ] Register with NetworkingDriverKit and expose as ethernet interface
- [ ] Test throughput vs CDC baseline
- [ ] Set up SIP-disabled dev machine for iteration
- [ ] Notarize and distribute once entitlements approved

## References

- Linux kernel aqc111 driver: `drivers/net/usb/aqc111.c`
- Apple DriverKit documentation: https://developer.apple.com/documentation/driverkit
- USBDriverKit: https://developer.apple.com/documentation/usbdriverkit
- NetworkingDriverKit: https://developer.apple.com/documentation/networkingdriverkit

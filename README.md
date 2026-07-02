# AQC111Driver

A macOS DriverKit system extension for USB Ethernet adapters based on the AQTION AQC111U chipset, delivering up to 5 Gbps Ethernet over USB 3.0.

AQTION shipped a working x86 IOKit kext for macOS but **never wrote a DriverKit replacement**. Apple deprecated third-party kexts in favour of DriverKit from macOS Catalina onwards, a direction that Apple Silicon only reinforced. The x86 kext worked until it didn't, and no replacement followed — leaving these adapters silently falling back to the slow CDC Ethernet path, or not working at all. This driver is the DriverKit replacement they never shipped.

Tested device: **TRENDnet TUC-ET5G** (VID `0x20f4`, PID `0xe05a`).

Thanks to Apple for approving the `driverkit.transport.usb` and `driverkit.family.networking` entitlements for this project, making it possible to develop a proper DriverKit driver for this hardware.

As far as could be determined, this is the first published open-source DriverKit + Skywalk (`IOUserNetworkEthernet`) driver for real, physical hardware — public DriverKit networking examples are otherwise limited to Apple's own sample code. Large parts of what's needed to make a real network driver work this way (queue topology, OSAction dispatch quirks, checksum/MTU capability negotiation, sticky hardware registers across driver restarts, and more) are weakly documented or entirely undocumented by Apple. This project is published in that spirit as much as for the driver itself: a working reference for the parts of DriverKit networking that aren't covered by sample code, so the next person doesn't have to rediscover them from scratch.

---

## Background

The AQC111U exposes two USB configurations:

| Config | Class | Speed | macOS default? |
|--------|-------|-------|----------------|
| 1 — "LAN" | Vendor-specific (class 255) | Up to 5 Gbps | No |
| 2 | CDC Ethernet (class 10) | Slow | **Yes** |

macOS binds to Config 2 by default. This driver forces Config 1 and implements the full Ethernet stack on top of it.

---

## Architecture

Two DriverKit personalities in a single dext bundle:

### Personality A — AQC111 (device, `IOUserService`)
- Matches `IOUSBHostDevice` (VID/PID)
- Calls `SetConfiguration(1, matchInterfaces: true)` to switch to the fast config and publish `IOUSBHostInterface` nubs
- Holds the USB device session open for the lifetime of the driver — this pins Config 1; releasing the session causes macOS to revert to Config 2

### Personality B — AQC111NIC (`IOUserNetworkEthernet`)
- Matches `IOUSBHostInterface` (Config 1, `bInterfaceClass=255`)
- Uses `CopyDevice()` for control transfers — it does **not** open the device itself; Personality A holds the exclusive session
- Registers an `en` Ethernet interface via Skywalk (`RegisterEthernetInterface`)
- Posts async IO on bulk RX/TX pipes and an interrupt pipe for link status

---

## Current Status

The driver loads, forces Config 1, registers an Ethernet interface, and has grown well past basic Ethernet connectivity: RX and TX hardware checksum offload, jumbo frame/MTU control, and runtime-controllable diagnostics are all implemented and validated (see below). The complete bidirectional data path — RX and TX — is confirmed working end-to-end: ARP resolves, and `ping` succeeds.

**What works:**
- USB enumeration with Config 1 forced (vendor-specific high-performance path)
- Ethernet interface registered (`en10`, MAC read from hardware)
- PHY bring-up and link negotiation (up to 5000baseT full-duplex confirmed)
- `ifconfig enX up` / `ifconfig enX down` — link comes up and down correctly
- End-to-end RX: frames arrive in Wireshark and tcpdump
- End-to-end TX: ARP resolves, `ping` succeeds
- RX checksum offload — validated end-to-end against deterministic good/bad-checksum test traffic, including the IP/TCP error-interaction edge case; see `TESTING.md` and `IMPL_PLAN.md` M6a
- TX checksum offload — validated end-to-end including a genuine hardware-reset negative control; see `TESTING.md` and `IMPL_PLAN.md` M6b
- Jumbo MTU control — reports and applies MTU up to 16334; jumbo ICMP traffic
  validated up to 16 KB-class frames with matching peer hardware, with 4K
  streaming stable at both MTU 1500 and configured MTU 16334; see `TESTING.md`
- Software 802.1Q VLAN support via macOS `vlan(4)` — validated with VLAN
  `1234` bidirectional ICMP over a clean `/24` test rig, parent-interface
  capture showing inline `802.1Q` tags on the wire, `vlan0` capture showing
  decapsulated IPv4, and a mismatched-VLAN negative control (`1235`) proving
  VLAN ID demux/filtering works; see `TESTING.md` and `IMPL_PLAN.md` M6e
- Runtime MAC address override (`ifconfig en9 lladdr ...`) — validated
  end-to-end including a remote-side capture confirming the new address live
  on the wire, a fresh DHCP lease, and confirmation the override is
  volatile/safe across a genuine power cycle (not a durable EEPROM rewrite);
  see `TESTING.md` and `IMPL_PLAN.md` M6j
- Forced media selection (`ifconfig en9 media 100baseTX`/`2500base-T`/...) —
  validated end-to-end across 100M/2.5G (cross-confirmed by the link
  partner's own `ethtool` for the 2.5G case), survives an interface
  disable/enable cycle, and reverting to `autoselect` correctly climbs back
  to the link's actual max, including 5G on a capable peer; see `TESTING.md`
  and `IMPL_PLAN.md` M6f
- Promiscuous mode — validated by actually changing what frames the
  hardware admits (a foreign-destination-MAC frame, invisible without it,
  becomes visible on the wire once enabled and invisible again once
  disabled), not just a register write with assumed effect; see
  `TESTING.md` and `IMPL_PLAN.md` M6g
- Multicast filtering — per-address CRC32-hash filtering (`SetMulticastAddresses`)
  validated end-to-end including real UDP socket delivery for an admitted
  group and a deliberately non-colliding address confirmed still dropped;
  the accept-all-multicast fallback for when the address count exceeds the
  64-bucket hash table's capacity validated to genuinely bypass per-address
  filtering, not just set a bit with assumed effect; see `TESTING.md` and
  `IMPL_PLAN.md` M6h

**What is not done yet:**
- TSO — firmware-based TCP segmentation via TX descriptor MSS field
- Hardware VLAN tag insert/strip — the AQC111U supports this in silicon and
  the RX/TX descriptors carry VLAN metadata, but the current supported path is
  software `vlan(4)` with inline 802.1Q tags. Hardware offload is confirmed
  blocked via Apple DTS and verified empirically (declaring the undocumented
  BSD `IF_HWASSIST_VLAN_TAGGING` value `0x00010000` is ignored wholesale, and
  the OS never calls either generation of `setHardwareAssists`); the SDK
  doc/header inconsistency is filed as `FB23530504`. See `IMPL_PLAN.md` M6e
  and `TESTING.md` "VLAN Support" Step 2.
- Wake-on-LAN — magic packet path exists in hardware; not wired up
- PHY access polymorphism — the AQC111U has two PHY control interfaces selected by firmware major version (`>= 0x80` → `FWPhyAccess` via bRequest=0x61; `< 0x80` → `DirectPhyAccess` via bRequest=0x31/0x32). The driver reads and logs the firmware version at start but unconditionally uses the `FWPhyAccess` path. This is correct for the DUT (firmware `major=0x82`). Support for older `DirectPhyAccess` devices is not implemented.
- TX ring depth — the TX path submits one frame at a time and waits for USB completion before submitting the next (`txBusy`/`txInFlight` single-slot gate). RX uses 10 outstanding buffers in flight; TX has no equivalent pipelining, which caps achievable throughput well short of the link's 5 Gbps ceiling under sustained load.
- RX copy path — this driver does one `memcpy` per received frame (raw USB buffer → packet pool), the same as Linux, because the RX buffer is reused in-place and must be reposted immediately. The x86 kext achieves zero payload copies via a different strategy (fresh mbuf allocation every cycle + zero-copy mbuf splitting) not directly portable to this driver's model. Separately, RX/TX/ITR buffers use the generic `IOBufferMemoryDescriptor::Create()` allocator rather than `IOUSBHostInterface::CreateIOBuffer()`, which is documented to avoid USB DMA bounce-buffering — unconfirmed whether this is a measurable throughput cost in practice, since Apple's own `IODMACommand` documentation states it doesn't bounce-buffer by itself either way. See `IMPL_PLAN.md` M9.
- `hwAssistMask` is not enforced for TX checksum or VLAN tagging — RX checksum offload correctly honors `SetHardwareAssists`, but TX checksum and inline VLAN-tag preservation happen unconditionally regardless of what the OS has enabled (e.g. `ifconfig -txcsum` has no observable effect on the wire). See `IMPL_PLAN.md` M6i.

**Current bugs:**

1. **Teardown leaves corpse processes that block reinstall.** After uninstall, both personalities leave orphaned dext processes that sysextd waits on indefinitely rather than force-killing. A reboot is not required — sending `SIGTERM` to all corpse processes after uninstall is almost always sufficient to allow reinstallation. The underlying cause (why `Stop()` RPCs go undeliverable and sysextd doesn't recover) should be studied and corrected.

2. **RX silently stops mid-session; TX keeps working.** Confirmed recurring (three occurrences so far). Root cause identified: a `kIOReturnNotResponding` device hiccup leaves USB pipes stalled afterward, and the driver has three separate gaps in stall recovery — one per pipe (RX, ITR, TX) — each missing a different shape of the same problem (stall-as-completion-status on RX not handled outside the `kUSBHostReturnPipeStalled` case; stall-as-resubmission-return-value on ITR and TX never checked at all). Recovery requires unplugging/re-enumerating the device. Fix plan documented in `IMPL_PLAN.md`; not yet implemented — collecting more occurrences first to confirm it covers all observed patterns before spending implementation effort.

---

## Provisioning Requirements

This dext requires two entitlements that are not available by default:

| Entitlement | Purpose |
|-------------|---------|
| `com.apple.developer.driverkit.transport.usb` | USB DriverKit access |
| `com.apple.developer.driverkit.family.networking` | Skywalk / `IOUserNetworkEthernet` |
| `com.apple.developer.driverkit.allow-any-userclient-access` | Allows the diagnostic log-level tool to open the NIC `IOUserClient` |

Both are available for **development** through the Apple Developer portal (request via the Additional Capabilities form). Distribution entitlements require a separate request to Apple and are granted case-by-case. The author holds distribution-level entitlements for both.

The provisioning profile must include all dext entitlements (`driverkit`, `transport.usb`, `family.networking`, and `allow-any-userclient-access`). Build with `CODE_SIGN_STYLE=Manual` pointing at that profile; Xcode's built-in codesign is sufficient — no post-build re-sign script is needed.

**SIP does not need to be disabled.** The driver builds and loads under normal SIP-on operation. Disabling SIP (`csrutil disable` / `amfi_get_out_of_my_way=1`) is a last resort for development iteration when provisioning is unavailable, but it is not required and should not be the normal workflow.

---

## Build & Install

1. Open `AQC111/AQC111.xcodeproj` in Xcode
2. Build both the **AQC111** (dext) and **AQC111Loader** (app) targets
3. Run the loader app from DerivedData
4. On first install: approve the extension in **System Settings → General → Login Items & Extensions → Driver Extensions**
5. Subsequent runs of the loader replace the installed dext automatically

**To uninstall:**
```
systemextensionsctl uninstall R83642DDMF au.com.jquirke.AQC111Driver
```

If the system extension state becomes tangled (ENOEXEC on dext launch, stuck in "activating"), uninstall and reboot to clear kernel state.

---

## Diagnostics

Stream dext logs:
```
log stream --predicate 'process == "kernel" AND eventMessage contains "AQC111"' --level debug
```

DriverKit dext `os_log` output is attributed to the `kernel` process.

**Log verbosity is runtime-controllable** (see `IMPL_PLAN.md` "Log Level Strategy"): defaults to Info via the `AQC111LogLevel` key in `Info.plist`, and can be raised/lowered live without reinstalling via `tools/set-log-level.swift <0-3>` (0=Error, 1=Info, 2=Debug, 3=Verbose — Debug/Verbose include per-packet and hex-dump logging, off by default).

Test methodology and results for features that need more than "it compiled" as evidence — e.g. the RX checksum offload validation — are tracked in `TESTING.md`.

---

## Design Lessons

Anyone who has done kernel debugging on other platforms will recognise the value of a two-machine setup early — one machine running the driver, another attached for kernel-level inspection. Some of these lessons were learned without that luxury, which is the most thorough way to learn them.

**OSAction callbacks require IIG factory methods.** Raw `OSAction::Create()` produces `OSTypeID(OSAction)`, but the IIG-generated `_Dispatch` switch gates every callback on a typed subclass ID (`OSTypeID(OSAction_ClassName_MethodName)`). The type mismatch causes silent, complete callback drops — no log, no error. Always use `CreateActionOnMethodName()`.

**Never replace the "Default" dispatch queue.** The networking framework installs a kernel-side proxy queue at the "Default" slot in `Start_Impl`. `Stop_Impl` cancels this queue internally and its async completion block dereferences a field at `+0x10` from the proxy's backing object. Replacing "Default" with a plain `IODispatchQueue` puts a null there and crashes at `Stop_Impl+144`. The dext-owned queue should be registered as `"RxDispatchQueue"` / `"TxDispatchQueue"` (the IIG-named Skywalk slots), not as "Default".

**`IOProviderClass` must be `IOUSBHostInterface` for the NIC personality.** Matching on `IOUSBHostDevice` allows `Start()` to succeed and direct method calls to work, but `IOUSBHostPipe` async IO completions are routed through the interface node — a driver matched on the device node is outside that delivery path and never receives callbacks.

---

## References

- Linux kernel driver: [`drivers/net/usb/aqc111.c`](https://github.com/torvalds/linux/blob/master/drivers/net/usb/aqc111.c)
- Apple DriverKit sample: *Connecting a Network Driver* (available on the Apple Developer portal)
- AQC111U register map: cross-referenced from the Linux driver source and the original macOS x86 kext (v1.4.4, bundle ID `com.aquantia.driver.usb.pacific`)

---

*Shamelessly vibecoded by an experienced systems engineer with the assistance of [Claude Sonnet 4.6](https://anthropic.com) and GPT-5.4.*

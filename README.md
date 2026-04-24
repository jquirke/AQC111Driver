# AQC111Driver

A macOS DriverKit system extension for USB Ethernet adapters based on the AQTION AQC111U chipset, delivering up to 5 Gbps Ethernet over USB 3.0.

AQTION shipped a working x86 IOKit kext for macOS but **never wrote a DriverKit replacement**. Apple deprecated third-party kexts in favour of DriverKit from macOS Catalina onwards, a direction that Apple Silicon only reinforced. The x86 kext worked until it didn't, and no replacement followed — leaving these adapters silently falling back to the slow CDC Ethernet path, or not working at all. This driver is the DriverKit replacement they never shipped.

Tested device: **TRENDnet TUC-ET5G** (VID `0x20f4`, PID `0xe05a`).

Thanks to Apple for approving the `driverkit.transport.usb` and `driverkit.family.networking` entitlements for this project, making it possible to develop a proper DriverKit driver for this hardware.

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

### Key design lessons (hard won)

Anyone who has done kernel debugging on other platforms will recognise the value of a two-machine setup early — one machine running the driver, another attached for kernel-level inspection. Some of these lessons were learned without that luxury, which is the most thorough way to learn them.

**OSAction callbacks require IIG factory methods.** Raw `OSAction::Create()` produces `OSTypeID(OSAction)`, but the IIG-generated `_Dispatch` switch gates every callback on a typed subclass ID (`OSTypeID(OSAction_ClassName_MethodName)`). The type mismatch causes silent, complete callback drops — no log, no error. Always use `CreateActionOnMethodName()`.

**Never replace the "Default" dispatch queue.** The networking framework installs a kernel-side proxy queue at the "Default" slot in `Start_Impl`. `Stop_Impl` cancels this queue internally and its async completion block dereferences a field at `+0x10` from the proxy's backing object. Replacing "Default" with a plain `IODispatchQueue` puts a null there and crashes at `Stop_Impl+144`. The dext-owned queue should be registered as `"RxDispatchQueue"` / `"TxDispatchQueue"` (the IIG-named Skywalk slots), not as "Default".

**`IOProviderClass` must be `IOUSBHostInterface` for the NIC personality.** Matching on `IOUSBHostDevice` allows `Start()` to succeed and direct method calls to work, but `IOUSBHostPipe` async IO completions are routed through the interface node — a driver matched on the device node is outside that delivery path and never receives callbacks.

---

## Current Status

The driver loads, forces Config 1, registers an Ethernet interface, opens all pipes, and successfully receives async IO callbacks. The MAC address is read from hardware. Link state is parsed from the interrupt pipe, and manual interface up/down now works end-to-end through `ifconfig`.

**What works:**
- Config 1 selection and session pinning
- NIC personality match and `Start()` completion
- All three pipe callbacks (RX, ITR, timer diagnostic) confirmed firing
- MAC address read from hardware
- PHY bring-up now produces a real link-up event
- Link status reporting (up/down, speed code) and media decoding
- Manual `ifconfig enX up` / `ifconfig enX down` soft enable/disable path
- Soft disable aborts RX/ITR, withdraws PHY advertisement, enters low power, and reports link down

**What is not done yet:**
- RX frame parsing: the DMA aggregation header sits at the **end** of the buffer (last 8 bytes), not the beginning — parsing logic needs fixing
- TX path not yet implemented
- End-to-end packet flow not yet validated
- Automatic lifecycle handling is still incomplete: attach/detach, repeated development cycles, and reattach can still regress into a stuck state that may require a reboot
- The current validated control path is still manual (`ifconfig`), not a polished automatic bring-up/shutdown flow

---

## Provisioning Requirements

This dext requires two entitlements that are not available by default:

| Entitlement | Purpose |
|-------------|---------|
| `com.apple.developer.driverkit.transport.usb` | USB DriverKit access |
| `com.apple.developer.driverkit.family.networking` | Skywalk / `IOUserNetworkEthernet` |

Both are available for **development** through the Apple Developer portal (request via the Additional Capabilities form). Distribution entitlements require a separate request to Apple and are granted case-by-case. The author holds distribution-level entitlements for both.

The provisioning profile must include all three dext entitlements (`driverkit`, `transport.usb`, `family.networking`). Build with `CODE_SIGN_STYLE=Manual` pointing at that profile; Xcode's built-in codesign is sufficient — no post-build re-sign script is needed.

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

Stream dext logs (filter out runningboard noise):
```
log stream --predicate 'eventMessage contains "AQC111" AND subsystem != "com.apple.runningboard"' --level debug
```

---

## References

- Linux kernel driver: [`drivers/net/usb/aqc111.c`](https://github.com/torvalds/linux/blob/master/drivers/net/usb/aqc111.c)
- Apple DriverKit sample: *Connecting a Network Driver* (available on the Apple Developer portal)
- AQC111U register map: cross-referenced from the Linux driver source and the original macOS x86 kext (v1.4.4, bundle ID `com.aquantia.driver.usb.pacific`)

---

*Shamelessly vibecoded by an experienced systems engineer with the assistance of [Claude Sonnet 4.6](https://anthropic.com) and GPT-5.4.*

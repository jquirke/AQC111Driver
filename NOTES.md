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
- Old macOS kext for x86 (`~/trendiokit/`) — disassembled; bundle ID `com.aquantia.driver.usb.pacific`, v1.4.4, built for macOS 10.13
- Previous DriverKit skeleton on GitHub (to be located and reviewed)

### Old KEXT Matching Strategy (from `~/trendiokit/Contents/Info.plist`)

The original KEXT used **two IOKitPersonalities**:

1. **Device-level** (`IOProviderClass: IOUSBHostDevice`, `IOClass: AppleUSBHostCompositeDevice`):
   - Sets `kUSBPreferredConfiguration: 1` — delegates to Apple's built-in composite device class to force Config 1 selection
   - Does not run any vendor code; purely a config selection hint

2. **Interface-level** (`IOProviderClass: IOUSBHostInterface`, `IOClass: AqPacificDriver`):
   - `bInterfaceNumber: 0`, `bConfigurationValue: "*"` (any config)
   - Actual driver code runs here, after Config 1 is already selected

**Why this matters for DriverKit:**
Our current approach (single device-level DriverKit driver that calls `SelectConfiguration(1)` in `Start()`) is equivalent but consolidated into one driver. The KEXT split it because kernel drivers couldn't easily call SelectConfiguration themselves and needed Apple's composite device class to do it. DriverKit's `IOUSBHostDevice` API exposes `SelectConfiguration()` directly, so the two-personality trick is not needed.

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

- **Local dev (pre-entitlement approval)**: SIP disabled (Permissive Security in recoveryOS), `systemextensionsctl developer on`
- **Entitlements**: `com.apple.developer.driverkit.transport.usb` requires Apple approval OR SIP disabled. Base `com.apple.developer.driverkit` entitlement works with SIP on but is insufficient for USB access.
- **Provisioning**: Mac UDID `00006001-000A28380169401E` must be registered in Apple Developer portal for development profiles to include this device.
- **Deploy**: Build phase script copies `AQC111Loader.app` to `/Applications/` automatically. Run from there (not from Xcode) for system extension activation.
- **Target**: Apple Silicon Mac, macOS Sequoia/26.x

## Current State (session 5)

### Completed
- [x] Xcode project set up: dext target + loader app target
- [x] Info.plist, entitlements, AppDelegate.swift wired up correctly
- [x] Dext embedded in loader app at `Contents/Library/SystemExtensions/`
- [x] SIP disabled (Permissive Security) + `systemextensionsctl developer on` — loader no longer needs to be in /Applications
- [x] `com.apple.developer.driverkit.transport.usb` added to dext entitlements (array-of-dicts format matching provisioning profile)
- [x] Provisioning profile "DriverKit AQC111" includes USB transport (dev) capability — manual signing configured
- [x] Dext activates, loads, passes entitlements check (`[activated enabled]`) ✓
- [x] `Stop()` implemented: `Stop(provider, SUPERDISPATCH)` — prevents `terminating_for_upgrade_via_delegate` from getting stuck
- [x] Loader app updated: Install / Uninstall buttons; no longer auto-activates on launch
- [x] `Open(this, 0, 0)` removed — returns `kIOReturnUnsupported` (0xe00002c7) when driver inherits from IOUSBHostDevice (driver IS the device; Open is for external clients only)
- [x] `Start()` now calls `SetConfiguration(1, true)` directly without Open — **pending verification after next reboot**

### Next Steps
- [ ] **Reboot** to clear tangled extension state (`terminating for uninstall but still running`)
- [ ] Build, click Install in loader app, approve in System Settings if prompted
- [ ] Verify `SetConfiguration(1) succeeded` in Console logs
- [ ] Verify CDC does NOT load (no unexpected `en` interface)
- [ ] Open interface 0 from Config 1, then open bulk IN/OUT and interrupt pipes
- [ ] Implement AQC111 init sequence (reference: Linux `aqc111` driver + `~/trendiokit/`)
- [ ] Implement RX/TX bulk transfer loop
- [ ] Implement interrupt EP handler for link status
- [ ] Register with NetworkingDriverKit and expose as ethernet interface
- [ ] Test throughput vs CDC baseline
- [ ] Notarize and distribute once entitlements approved

### Apple DriverKit SDK Guidance (from Creating a Driver Using the DriverKit SDK)

**Driver roles:**
- **Device service** — supports custom communication protocols or configures hardware (e.g. `IOUSBHostDevice`). Our device-level `AQC111` is a device service.
- **Interface service** — reads/writes data and processes it (e.g. `IOUserNetworkEthernet`). Our future networking driver will be an interface service.

**No member variables in service class.** Use an IVars struct:
```cpp
struct AQC111_IVars { /* fields */ };
// In .iig: struct AQC111_IVars; struct AQC111_IVars *ivars;
// In init(): ivars = IONewZero(AQC111_IVars, 1);
// In free(): IOSafeDeleteNULL(ivars, AQC111_IVars, 1); super::free();
```

**Start() template (Apple docs):**
```cpp
IMPL(MyDriver, Start) {
    ret = Start(provider, SUPERDISPATCH);  // super first
    if (ret != kIOReturnSuccess) { Stop(provider, SUPERDISPATCH); return ret; }
    // ... startup tasks ...
    RegisterService();  // required — tells system driver is ready
    return ret;
}
```
Note: for device-level drivers that must configure the device before interface matching (our case), Open/SetConfiguration must come before `Start(SUPERDISPATCH)` — as in VendorSpecificUSBDriverKitSample.

**Required Info.plist keys (install will FAIL without these):**
- `CFBundleShortVersionString`
- `CFBundleVersion`
- `OSBundleUsageDescriptionKey`

**Required personality keys in `IOKitPersonalities`:**
- `CFBundleIdentifier` — bundle ID of driver
- `IOClass` — Apple base class (e.g. `IOUserService`)
- `IOUserClass` — name of your custom service class
- `IOUserServerName` — bundle ID of driver (again)
- `IOProviderClass` — provider class (e.g. `IOUSBHostDevice`)

**IMPL / SUPERDISPATCH:** `IMPL` macro provides kernel bridging for your method; `SUPERDISPATCH` provides reverse bridging to call inherited kernel-side methods.

### USBDriverKit API Notes
- `SetConfiguration(bConfigurationValue, matchInterfaces)` — not `SelectConfiguration`; takes bConfigurationValue (not index), bool matchInterfaces
- **Driver must inherit from `IOService`, NOT `IOUSBHostDevice`**. When inheriting `IOUSBHostDevice`, both `Open(this,0,0)` and `SetConfiguration()` on `this` return `kIOReturnUnsupported` (0xe00002c7) — these are client-side APIs. The driver is not a client of itself.
- Correct pattern (confirmed by VendorSpecificUSBDriverKitSample):
  1. Inherit `IOService`; keep `IOProviderClass=IOUSBHostDevice` in Info.plist (matching unaffected)
  2. `OSDynamicCast(IOUSBHostDevice, provider)` to get typed device pointer
  3. `device->Open(this, 0, 0)` — now `this` (IOService) is a client of the device
  4. `device->SetConfiguration(1, true)` — sets config, publishes interface nubs for child matching
  5. `Start(provider, SUPERDISPATCH)` — super Start
  6. **`RegisterService()`** — **required** when inheriting IOService; without it the OS assumes Start failed and no interface matching occurs
- `com.apple.developer.driverkit.transport.usb` entitlement format: `<array><dict><key>idVendor</key><string>*</string></dict></array>` (not `<true/>`)
- systemextensionsctl tangled state: requires reboot to clear. Uninstall via deactivationRequest also leaves "terminating for uninstall but still running" if dext is active — reboot required.

## Known Bugs (session 26, 2026-04-24)

Observed via `log stream --predicate 'eventMessage contains "AQC111" AND process == "kernel"'` after `ifconfig en10 up` with no cable.

### OBSERVATION: Re-enumeration delayed after unplug (not a zombie)

On USB unplug, the dext teardown burns 2 corpse slots (one per personality process).
The second corpse hits the system limit: `Corpse failure, too many 6`. After this,
re-plugging the USB device appears to do nothing — no `Start ENTERED` in logs.
However, after ~a few minutes the device re-enumerates and the driver reattaches
normally. Likely cause: kernel is delaying re-match until internal cleanup from the
failed corpse accounting completes. Not a zombie. Reboot resets corpse budget.

**Development implication:** budget is ~2 unplug cycles per boot before this delay
appears. Plan test sequences to minimize unplugs, reboot to reset.

### VERIFIED: PHY bring-up now produces link-up and correct media selection

After replacing the one-shot PHY init with the Linux/x86-style bring-up model
(explicit PHY power-on, pre-advertise clears, stateful `AQ_PHY_OPS`, deferred
medium enable), `ifconfig en10 up` now produces a real link-up interrupt:

- `SetInterfaceEnable: 1`
- `hwEnable: AQ_PHY_POWER=0x02 -> 0x0`
- `hwEnable: AQ_PHY_OPS flags=0x072b000f -> 0x0`
- `ITR: byte1=0x91 linkUp=1 speed=0x11 -> reportLinkStatus(0x3, 0x500030)`

This is the first confirmed transition from the earlier no-link state to
device-reported link-up.

### VERIFIED: media decoding path is correct

The interrupt handler decodes the hardware speed byte correctly:

- `0x0F` -> `5000BaseT`
- `0x10` -> `2500BaseT`
- `0x11` -> `1000BaseT`
- `0x13` -> `100BaseTX`

The observed link-up event carried `speed=0x11`, and the driver reported the
matching NetworkingDriverKit media word (`1000BaseT` full duplex with flow
control). So the current issue is not incorrect media decoding.

Direct userland confirmation after `sudo ifconfig en10 up`:

- `media: autoselect (1000baseT <full-duplex>)`
- `status: active`

### REMAINING BUG: zombie / teardown lifecycle still regresses after some cycles

The driver can still end up in a zombie / stuck lifecycle state after repeated
attach-detach or development cycles, requiring a reboot to recover cleanly.
That is now separate from PHY/media correctness:

- PHY bring-up can produce link-up
- media reporting follows the ITR speed code correctly
- remaining instability is in lifecycle / teardown / reattach behavior

### NEXT WORK

- make `ifconfig en10 down` a reversible soft shutdown:
  stop reposting RX/ITR, withdraw advertisement, enter PHY low power, report link down
- keep full PHY power-off for deeper stop / unplug / termination paths
- investigate why the dext can still zombie and require reboot after some runs

## References

- Linux kernel aqc111 driver: `drivers/net/usb/aqc111.c`
- **VendorSpecificUSBDriverKitSample** (Xbox One controller → HID via DriverKit): https://github.com/Drewbadour/VendorSpecificUSBDriverKitSample
  - Exact same two-stage pattern: device-level `IOService` driver sets config → interface-level driver does the work
  - Source of truth for: IOService inheritance, OSDynamicCast, Open→SetConfig→Start(SUPERDISPATCH)→RegisterService order, IVars pattern
- Apple DriverKit documentation: https://developer.apple.com/documentation/driverkit
- USBDriverKit: https://developer.apple.com/documentation/usbdriverkit
- NetworkingDriverKit: https://developer.apple.com/documentation/networkingdriverkit

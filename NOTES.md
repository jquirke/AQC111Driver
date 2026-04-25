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

### VERIFIED: manual end-to-end `ifconfig up/down` works

The NIC now responds correctly to manual interface state changes from userland:

- `ifconfig en10 up` triggers `SetInterfaceEnable: 1`, arms RX/ITR async IO,
  runs `hwEnable`, and produces the expected link pulse / active media state
- `ifconfig en10 down` triggers `SetInterfaceEnable: 0`, aborts RX/ITR cleanly,
  withdraws PHY advertisement, enters PHY low power, and reports link inactive

Observed RX completions with `status=0xe00002eb` after `ifconfig ... down` are
expected abort completions from the deliberate `disarmAsyncIO` path, not a new
data-path failure.

Current limitation: this is still a manual control path validated via
`ifconfig`. Automatic lifecycle handling across attach, detach, and repeated
development cycles still needs work.

### REMAINING BUG: zombie / teardown lifecycle still regresses after some cycles

The driver can still end up in a zombie / stuck lifecycle state after repeated
attach-detach or development cycles, requiring a reboot to recover cleanly.
That is now separate from PHY/media correctness:

- PHY bring-up can produce link-up
- manual `ifconfig en10 up/down` is end-to-end functional
- media reporting follows the ITR speed code correctly
- remaining instability is in lifecycle / teardown / reattach behavior

### NEXT WORK

- wire the now-working soft up/down path into broader automatic lifecycle handling
- keep full PHY power-off for deeper stop / unplug / termination paths
- investigate why the dext can still zombie and require reboot after some runs

## Reboot Handoff (session 27, 2026-04-25)

Current live branch contains an uncommitted experimental patch in
`AQC111/AQC111/AQC111NIC.cpp` that adds:

- `hwOnLinkUp(speedCode)`
- `hwOnLinkDown()`
- explicit `rxStarted` state
- `ensureRxStarted()` / `ensureRxStopped()` helpers

Intent of the patch:

- keep `interfaceEnabled`, `lastLinkUp`, and `rxStarted` as separate concepts
- move RX producer start/stop into an explicit state machine
- program the missing x86/Linux-style receive-start registers on link-up:
  - `SFR_RX_CTL = 0`
  - `SFR_ETH_MAC_PATH = 1`
  - `SFR_BULK_OUT_CTRL = 2`
  - RX coalescing at `0x002e..0x0032`
  - `SFR_MEDIUM_STATUS_MODE`
  - `SFR_MEDIUM_STATUS_MODE |= RECEIVE_EN`
  - `SFR_VLAN_ID_CONTROL = 0x10`
  - final `SFR_RX_CTL = 0x0288`

Important caveat from reasoning review:

- this model is still only a diagnostic experiment
- Jeremy's concern remains valid that the interrupt path may only provide
  edge-triggered link events after `ifconfig en10 up`
- so the current patch may still be insufficient even though the state model
  is cleaner than the earlier `lastLinkUp` edge guard

Post-reboot validation target:

- build/install the current tree
- run `ifconfig en10 up`
- watch for exactly:
  - `OnRxComplete: slot=N status=0x0 bytes=...`

Interpretation:

- if bulk RX completions appear, the missing receive-start sequence was a real
  blocker
- if bulk RX remains silent, likely next steps are:
  - stop relying solely on interrupt-driven RX-start in this port
  - consider triggering RX-start from the happy-path enable side after ITR arm
  - add missing x86 secondary writes (`0x0046`, `0x009e`) if still needed

## References

- Linux kernel aqc111 driver: `drivers/net/usb/aqc111.c`
- **VendorSpecificUSBDriverKitSample** (Xbox One controller → HID via DriverKit): https://github.com/Drewbadour/VendorSpecificUSBDriverKitSample
  - Exact same two-stage pattern: device-level `IOService` driver sets config → interface-level driver does the work
  - Source of truth for: IOService inheritance, OSDynamicCast, Open→SetConfig→Start(SUPERDISPATCH)→RegisterService order, IVars pattern
- Apple DriverKit documentation: https://developer.apple.com/documentation/driverkit
- USBDriverKit: https://developer.apple.com/documentation/usbdriverkit
- NetworkingDriverKit: https://developer.apple.com/documentation/networkingdriverkit

## Reboot Handoff (session 28, 2026-04-25)

State at handoff:

- Local tree contains further uncommitted edits in `AQC111/AQC111/AQC111NIC.cpp`
- Build was blocked in-session by code-signing, but one compile error discovered
  during editing (`hwDisable` forward declaration) was fixed locally
- No new runtime validation after those edits yet

Key findings from this session:

- RX is not fundamentally absent: on April 25, 2026, the dext logged real bulk
  RX completions with non-empty payloads:
  - `OnRxComplete: slot=0 status=0x0 bytes=432`
  - `OnRxComplete: slot=3 status=0x0 bytes=80`
  - similar repeats at `432` and `80` bytes
- Those same buffers were immediately rejected by the parser with:
  - `RX[n] bad header repost -> 0x0`
- So there are two separate issues:
  - reproducibility of the RX-active state
  - correct decoding of the RX buffer format

Code changes now present in `AQC111NIC.cpp`:

- Stronger `ifconfig up` reset path via `resetEnablePath(ivars)`:
  - `ensureRxStopped(ivars)`
  - `disarmAsyncIO(ivars)`
  - `hwDisable(ivars->interface)`
  - `ClearStall(false)` on ITR / RX / TX pipes
  - clear `lastLinkUp` / `rxStarted`
  - then normal `armAsyncIO(ivars)` + `hwEnable(...)`
- More permissive RX layout parser:
  - try aggregate header at offset `0`
  - try header at `actualByteCount - 8`
  - try header at `actualByteCount - 4`
  - accept only if `pkt_count`, `desc_off`, and packet lengths are internally consistent
- Bounded RX byte dump before parser rejection:
  - emits header `RXDUMP slot=N status=0x... bytes=N`
  - dumps full buffer for `bytes <= 512`
  - otherwise dumps first `64` and last `64`
  - first dump is latched once for `80`, once for `432`, and once for an
    unexpected size

Updated diagnosis:

- PHY/link and interrupt-driven media reporting are working
- bulk RX completions with payload are proven possible, but not deterministic
- `ifconfig up/down` was previously too shallow to recreate the earlier
  RX-active state; stronger reset path is now in-tree but unvalidated
- parser logic is still suspect until the real bytes from `80` / `432` buffers
  are captured by `RXDUMP`

Immediate post-reboot target:

- build/install the current tree
- run `ifconfig en10 up`
- watch for:
  - `resetEnablePath: ClearStall ...`
  - `OnRxComplete: slot=N status=0x0 bytes=...`
  - `RXDUMP slot=N status=0x... bytes=80`
  - `RXDUMP slot=N status=0x... bytes=432`

Interpretation:

- if stronger `ifconfig up` restores RX completions, next work is purely raw
  buffer interpretation and parser correction
- if RX completions still do not return, compare cold attach/start behavior
  against `SetInterfaceEnable(1)` reset behavior; missing state is probably
  deeper USB/runtime/device state rather than PHY/media

## Runtime Update (session 28, 2026-04-25 13:44)

After media reconnect, RX completions continued beyond the initial ten posted
slots. The apparent "up to 10 packets" pattern was a false lead caused by the
first pass through slots 0..9; later logs showed reposted slots completing
again:

- slot 0 completed again at `13:44:35` with `bytes=432`
- slot 1 completed again at `13:44:35` with `bytes=80`
- slot 2 completed again at `13:44:36` with `bytes=432`
- slots 3 and 4 completed again around `13:45:05` / `13:45:06`

Current RX interpretation:

- bulk RX reposting works
- the parser accepts the observed layouts:
  - `bytes=80`: `hdr=72 pkt_base=0 desc=64 count=1`
  - `bytes=96`: `hdr=88 pkt_base=0 desc=80 count=1`
  - `bytes=432`: `hdr=424 pkt_base=0 desc=416 count=1`
- the current driver reports `1/1 frames delivered` for these packets
- remaining question is now whether the delivered `IOUserNetworkPacket` range
  and completion queue behaviour are correct enough for the BSD interface /
  Skywalk path to consume packets

## Handoff Update (session 29, 2026-04-25)

Goal remains: get one packet visible in Wireshark.

Current constraints:

- teardown/uninstall can zombie the driver, making each runtime attempt a
  painful reboot loop
- therefore the next build should maximize diagnostic value in one run

Code now has additional RX diagnostics in `AQC111/AQC111/AQC111NIC.cpp`:

- dumps the first successful small aggregate buffers before parsing:
  - first `80` byte completion
  - first `432` byte completion
  - first other-size completion
- logs every delivered frame summary:
  - `pkt_len`
  - `frame_len`
  - destination MAC
  - source MAC
  - EtherType
- logs first 32 frame bytes for frames with `frame_len >= 32`
- constructs RX packets with stronger metadata:
  - `prepareWithQueue(rxcQueue, kIOUserNetworkPacketDirectionRx)`
  - `setDataOffsetAndLength(0, frame_len)`
  - `setLinkHeaderLength(14)`
  - `setCompletionStatus(kIOReturnSuccess)`
  - `EnqueuePacket(pkt)`
- logs all packet handoff return values:
  - `prepare`
  - `offLen`
  - `linkHdr`
  - `enqueue`
- if enqueue fails, deallocates the packet and logs that return value

Next-run interpretation matrix:

- valid dst/src/EtherType + all metadata/enqueue return `0x0` + no Wireshark:
  NetworkingDriverKit / Skywalk delivery path is suspect
- bad dst/src/EtherType:
  frame slice is still wrong
- `prepare`, `offLen`, or `linkHdr` fails:
  packet construction bug
- `enqueue` fails:
  RX completion queue / API usage bug

Next decisive milestone:

- either `enqueue=0x0` and Wireshark sees a packet
- or logs prove the packet boundary or Skywalk handoff is still wrong

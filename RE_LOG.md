# AQC111 Reverse Engineering Log

Source: `~/trendiokit/` — disassembled macOS x86 kext, bundle ID `com.aquantia.driver.usb.pacific`, v1.4.4

Tools: [Ghidra](https://ghidra-sre.org) (disassembly/decompilation), [Radare2](https://rada.re) (symbol lookup), [Claude](https://claude.ai) (analysis assistant)

---

## Driver Object Layout (com.aquantia.driver.usb.pacific)

| Offset | Field |
|--------|-------|
| 0x000  | `vtable*` → `__ZTV20IOEthernetController` (0x161c8) — IOEthernetController vtable pointer |
| 0x118  | `IONetworkInterface*` (populated by `attachInterface()` during start()) |
| 0x120  | `UsbHal*` (instance pointer, see UsbHal class below) |
| 0x128  | `_os_log_create` pointer |
| 0x130  | `OSDictionary*` Medium dictionary (stored during start()) |
| 0x138  | `Medium*` (pointer to Medium instance, 0x10 bytes, see Medium class below) |
| 0x140  | unknown |
| 0x150  | `Tx*` (pointer to Tx instance, 0x30 bytes, see Tx class below) |
| 0x158  | `Rx*` (pointer to Rx instance, 0x30 bytes, see Rx class below) |
| 0x160  | `Itr*` (pointer to Itr interrupt instance, 0x28 bytes, see Itr class below) |

## Driver Methods

### AqUsbHal::findEnpoints() (NB: typo in binary symbol — missing 'd')

Discovers and opens the three required USB pipes from Config 1.

```c
// Uses two StandardUSB static helpers (external symbols in binary):
//   StandardUSB::getEndpointAddress(EndpointDescriptor const*) → uint8_t
//   StandardUSB::getNextEndpointDescriptor(ConfigurationDescriptor const*,
//                                          InterfaceDescriptor const*,
//                                          Descriptor const*) → Descriptor const*
//
// IOUSBHostInterface vtable entries used:
//   vtable[0x9c0] — getInterfaceDescriptor() → InterfaceDescriptor const*
//   vtable[0x9b8] — getConfigurationDescriptor() → ConfigurationDescriptor const*
//   vtable[0xa80] — copyPipe(uint8_t endpointAddress) → IOUSBHostPipe*

InterfaceDescriptor*    ifDesc  = hal[0x08]->vtable[0x9c0]();  // getInterfaceDescriptor
if (ifDesc == null) return 0;   // fail

ConfigurationDescriptor* cfgDesc = hal[0x08]->vtable[0x9b8](); // getConfigurationDescriptor

// Iterate all endpoint descriptors in this interface
Descriptor* epDesc = getNextEndpointDescriptor(cfgDesc, ifDesc, NULL);
while (epDesc != NULL) {
    uint8_t addr = getEndpointAddress(epDesc);       // bEndpointAddress
    bool    in   = (epDesc->bEndpointAddress & 0x80) != 0;  // bit 7 = direction
    uint8_t type = epDesc->bmAttributes & 0x03;      // bits [1:0] = transfer type

    if (!in && type == 2) {
        hal[0x28] = hal[0x08]->vtable[0xa80](addr);  // bulk OUT → TX pipe
    } else if (in && type == 2) {
        hal[0x20] = hal[0x08]->vtable[0xa80](addr);  // bulk IN  → RX pipe
    } else if (in && type == 3) {
        hal[0x30] = hal[0x08]->vtable[0xa80](addr);  // interrupt IN → status pipe
    }

    epDesc = getNextEndpointDescriptor(cfgDesc, ifDesc, epDesc);
}

if (hal[0x20] == null) return 0;                     // RX pipe mandatory
return (hal[0x28] != null) && (hal[0x30] != null);   // need TX + interrupt too
```

Maps directly to device's Config 1 endpoints:
- EP1 IN Interrupt 16B → hal[0x30] (status pipe)
- EP2 IN Bulk 1024B   → hal[0x20] (RX pipe)
- EP3 OUT Bulk 1024B  → hal[0x28] (TX pipe)

### UsbHal::start(IOService* provider)

```
1. safeMetaCast(provider, IOUSBHostInterface) → store in hal[0x08]
2. hal[0x08]->IOService::open(hal[0x00], 0, 0)
   // interface->open(forClient=driver, options=0, arg=0)
   // forClient=hal[0x00] (IOEthernetController* back-pointer, since forClient must be IOService*)
3. hal[0x08]->IOUSBHostInterface::getDevice() — vtable[0xb80]; result (IOUSBHostDevice*) stored in hal[0x10]; null = fail
   (Ghidra misidentified as getCapabilityDescriptors — confirmed via IOUSBHostFamily vtable lookup)
4. hal[0x10]->IOUSBHostDevice::getConfigurationDescriptor() — vtable[0xa50]
   check: if configDesc->bConfigurationValue != 1 → alternate path:
       hal[0x10]->IOUSBHostDevice::setConfiguration(1, true) — vtable[0xb18], force config 1
       hal[0x4b] = 1   // reconfigured flag
5. (config 1 confirmed) hal[0x10]->IOUSBHostDevice::getDeviceDescriptor() — vtable[0xa38]; return value discarded (confirmed)
6. AqUsbHal::findEnpoints(hal)  // see above; populates hal[0x20], hal[0x28], hal[0x30]
   if findEndpoints fails → hal_start_fail
7. read firmware version (3 bytes) → hal[0x40..0x42]; R15B = hal[0x40] (major)
8. new(0x14); if (firmware_major >= 0x80) → FWPhyAccess::FWPhyAccess(obj, hal)
              else                        → DirectPhyAccess::DirectPhyAccess(obj, hal)
   hal[0x38] = obj
9. hal[0x38]->vtable[0x10](1)  // 3rd virtual — likely init/start; both subclasses converge here
   return success
```

### getMinPacketSize() / getMaxPacketSize()

Standard `IOEthernetController` overrides.

- `getMinPacketSize()` = `0x5a` = 90 bytes (larger than standard 64, likely USB framing overhead)
- `getMaxPacketSize()` = `0x3fe0` = 16352 bytes (large jumbo frame support)

### start() (IOService override)

Called on driver load/device attach.

```
1. super::start(provider)          // IOEthernetController::start()
2. UsbHal::start(provider)
3. Tx::start()
4. store Medium dictionary → driver[0x130]
5. `this->IONetworkController::attachInterface(interface**, false)` — vtable[0x9c0], doActivate=false; result stored at driver[0x118]
6. `IONetworkController::publishMediumDictionary(driver[0x130])` — publish supported media types to IOKit registry
7. `driver[0x118]->IOService::registerService(0)` — vtable[0x5b0], register network interface in IOKit registry
   (error) if 5, 6, or 7 fail → `IONetworkController::stop(provider)`, return error
```

### AqUsbHal::enable()

```
if (hal[0x57] != 0):
    call hal[0x38]->vtable[0x28](0)   // WoL resume: call 3rd virtual on PhyAccess obj with arg=0
else:
    call AqUsbHal::hwStart()          // normal bring-up sequence (see hwStart below)
hal[0x44] = 1   // enabled flag, set in both paths; return 1
```

### AqUsbHal::hwStart()

Full hardware init sequence executed on normal enable() (non-WoL path):

```
1. phyAccess->lowPower(false)              // vtable[0x18](0) — exit low-power mode

2. Read permanent MAC (bRequest=AQ_FLASH_PARAMETERS, IN, 6 bytes) → hal[0x45..0x4a]

3. Write MAC to reg 0x0010 (bRequest=AQ_ACCESS_MAC OUT, wLength=6, data=hal[0x45])

4. Write 0xff → reg 0x0041 (1 byte)

5. Write 0x00 → reg 0x00b1 (1 byte)

6. RMW reg 0x0024 (1 byte): val &= 0xe0               // clear bits [4:0]

7. RMW reg 0x000b (1 byte): if (val & 0x80) val &= 0x7f  // clear bit 7 if set

8. RMW reg 0x0022 (2 bytes): if (val & 0x0100) val &= 0xfeff  // clear bit 8 if set

9. RMW reg 0x00b0 (1 byte): if (val & 0x01) val &= 0xfe   // clear bit 0 if set

10. if (hal[0x58] == 0): hal[0x58] = 0x3f    // default: advertise all speeds

11. phyAccess->advertise(&hal[0x58])          // vtable[0x20] — configure AN advertisement
```

#### MediumFlags / hal[0x58]

`hal[0x58]` is a 1-byte speed advertisement bitmask passed to `advertise()`:

| bit | meaning |
|-----|---------|
| 0   | advertise 100 Mbps |
| 1   | advertise 1 Gbps |
| 2   | advertise 2.5 Gbps |
| 3   | advertise 5 Gbps |
| 4   | passed to FWPhyAccess fw[0x12] bit 0 |
| 5   | passed to FWPhyAccess fw[0x12] bit 1 |

Default value `0x3f` = all bits set = advertise all supported speeds.

For **FWPhyAccess** with `hal[0x58] = 0x3f`, the 4-byte firmware control struct sent via `bRequest=AQ_PHY_OPS` is:
```
fw[0x10] = 0x3f & 0x0f = 0x0f      // speed flags nibble
fw[0x11] = 0x00
fw[0x12] |= 0x20 | 0x01 | 0x02     // always-set bit + bits from MediumFlags[5:4]
fw[0x13]  = (fw[0x13] & 0xf0) | 0x07
```

### AqUsbHal::performUrb(To, void* context, IOMemoryDescriptor*, unsigned int size)

Submits an async USB I/O request on the appropriate pipe.

```c
enum To { TX = 0, RX = 1, ITR = 2 };

if (hal[0x44] == 0) return kIOReturnNotOpen;   // not enabled

// Each To value selects a pipe and a statically-instantiated completion wrapper:
//   TX  → hal[0x28] (bulk OUT),  onCompleteAction<AqUsbHal, &onTransmitComplete>  @ 0x1161
//   RX  → hal[0x20] (bulk IN),   onCompleteAction<AqUsbHal, &onReceiveComplete>   @ 0x1176
//   ITR → hal[0x30] (intr IN),   onCompleteAction<AqUsbHal, &onItrComplete>       @ 0x118b
switch (To) {
    case TX:  pipe = hal[0x28]; action = &onCompleteAction_TX;  break;
    case RX:  pipe = hal[0x20]; action = &onCompleteAction_RX;  break;
    case ITR: pipe = hal[0x30]; action = &onCompleteAction_ITR; break;
}

// Build IOUSBHostCompletion on the stack (24 bytes, 3 QWORDs):
IOUSBHostCompletion completion = {
    .owner     = hal,      // [+0x00] passed back as arg1 to action
    .action    = action,   // [+0x08] static fn ptr — the onCompleteAction wrapper
    .parameter = context,  // [+0x10] caller-supplied context, passed back as arg2
};

// IOUSBHostPipe::io() copies the completion struct internally — safe to pass stack ptr.
pipe->vtable[0x258](pipe, memdesc, size, &completion, /*timeout=*/0);
// vtable[0x258] = IOUSBHostPipe::io(IOMemoryDescriptor*, uint32_t length,
//                                   IOUSBHostCompletion*, uint32_t timeout)
```

#### onCompleteAction wrapper (template instantiation — identical body for all three)

When the USB transfer completes, the framework calls `action(owner, parameter, status, bytes)`.
The wrapper re-routes this into the driver's object hierarchy:

```c
// Signature: void onCompleteAction(void* owner, void* parameter, int status, uint32_t bytes)
// owner = hal (AqUsbHal*), parameter = caller context
if (hal[0x44] == 0) return;           // not enabled — drop silently
void* driver = hal[0x00];             // back-pointer to AqPacificDriver*
// Tail-call the driver-level handler (rdi replaced, rsi/rdx/rcx forwarded as-is):
AqPacificDriver::on{Itr,Receive,Transmit}Complete(driver, parameter, status, bytes);
```

The driver-level handler then loads the relevant subsystem object from the driver struct
(e.g. `driver[0x160]` = Itr*) and tail-calls into it.

Full wiring for ITR as example:
```
io() completes
  → onCompleteAction_ITR(hal, context=itr[0x18], status, bytes)
      check hal[0x44]; load hal[0x00]=driver*
      → AqPacificDriver::onItrComplete(driver*, context, status, bytes)
          load driver[0x160]=Itr*
          → Itr::onItrComplete(itr*, context, status, bytes)
              if status != 0: return   // error — drop, no re-post
              AqUsbHal::onInterruptEvent(itr[0x08], itr[0x18])
              → performUrb(ITR, itr[0x18], itr[0x20], 8)  // re-post (tail-call)
```

Callers:
- `Rx::refill()` — `performUrb(RX, entry, memdesc, 0x10000)`
- `Itr::start()` — `performUrb(ITR, itr[0x18], itr[0x20], 8)`
- `Tx::transmit(__mbuf*)` — `performUrb(TX, entry, memdesc, total_len)`

### AqPacificDriver::enable(IONetworkInterface*)

Standard `IOEthernetController` override — called when interface is brought up (ifconfig up).

```
1. AqUsbHal::enable()                                    // HAL enable (WoL or hwStart path)
2. IONetworkInterface::startOutputThread(interface, 0)   // start TX software output thread
3. IONetworkController::getOutputQueue() → queue         // vtable[0x918]; if non-null:
       getOutputQueue() → queue                          //   fetch again (canonical ref)
       IOOutputQueue::start()                            //   vtable[0x130]; start the HW output queue
4. Rx::start()                                           // driver[0x158]->Rx::start(), if non-null
5. IONetworkController::getSelectedMedium() → medium     // vtable[0x880]; if non-null:
       IONetworkController::setSelectedMedium(medium)    //   vtable[0x978]; re-apply medium selection
6. Itr::start()                                          // driver[0x160]->Itr::start()
7. return kIOReturnSuccess
```

### TX Output Thread

The kext uses two complementary TX paths, both feeding `Tx::transmit()`:

#### Path 1 — IONetworkingFamily output thread (`outputStart`)

`startOutputThread(interface, 0)` in `enable()` causes IONetworkingFamily to spawn a kernel
thread that calls `outputStart()` in a drain loop:

```c
// AqPacificDriver::outputStart(IONetworkInterface*, unsigned int flags)
if (driver[0x148] == 0)                // link down
    return kIOReturnNotReady;          //   thread stalls immediately

int rc = Tx::transmit(driver[0x150]); // pull from output queue, build SG, submit URB
// rc: 0=success/continue, 1=ring full, 2=alloc failed
if (rc == 0) return 0;                // thread loops and calls outputStart again
return kIOReturnNotReady;             // ring full or alloc fail — thread stalls
```

#### Path 2 — IOBasicOutputQueue (`outputPacket`)

`IOBasicOutputQueue` (created in `createOutputQueue()`) calls `outputPacket()` per-packet:

```c
// AqPacificDriver::outputPacket(__mbuf* mbuf, void* param)
if (driver[0x148] == 0) { mbuf_freem(mbuf); return 1; }  // link down → drop

int rc = Tx::transmit(driver[0x150], mbuf);
// rc 0 → return 0        (success)
// rc 1 → return 0x102    (kIOReturnOutputStall — queue stalls)
// rc 2 → mbuf_freem(mbuf); return 1  (alloc fail → drop)
```

#### Stall / unstall cycle

Every `Tx::onComplete()` tail-calls `onUnstallTxQueue()`:

```c
// AqPacificDriver::onUnstallTxQueue()
IOOutputQueue* queue = getOutputQueue();   // vtable[0x918]
if (queue != null) {
    if (queue->vtable[0x238]() & 2)        // queue is stalled?
        queue->vtable[0x140](1);           // IOOutputQueue::start() — restart it
}
signalOutputThread(driver[0x118]);         // wake the output thread (IONetworkInterface*)
```

`signalOutputThread()` calls `IONetworkInterface::vtable[0](interface, 0)` to wake the
stalled output thread so it re-enters `outputStart()`.

#### DriverKit note

NetworkingDriverKit replaces this entire mechanism with `txPacketsAvailable()`. The thread,
`IOBasicOutputQueue`, stall/unstall, and `signalOutputThread` are all kext-specific. Only
the `Tx::transmit()` logic needs to be replicated.

### hwStop

## Vendor Commands

### Named Constants

**bRequest values:**

| Name | Value | Description |
|------|-------|-------------|
| `AQ_ACCESS_MAC` | `0x01` | MAC register read/write (bulk, multi-byte) |
| `AQ_FLASH_PARAMETERS` | `0x20` | Read flash/EEPROM parameters (MAC address) |
| `AQ_PHY_POWER` | `0x31` | Direct PHY power control (DirectPhyAccess only) |
| `AQ_WOL_CFG` | `0x60` | Wake-on-LAN configuration |
| `AQ_PHY_OPS` | `0x61` | Firmware-mediated PHY operations (FWPhyAccess only) |

**AQ_ACCESS_MAC register addresses (wValue):**

| Name | Value | Description |
|------|-------|-------------|
| `AQ_FW_VER_MAJOR` | `0xDA` | Firmware version major byte |
| `AQ_FW_VER_MINOR` | `0xDB` | Firmware version minor byte |
| `AQ_FW_VER_REV` | `0xDC` | Firmware version revision byte |

**MediumFlags — 32-bit bitmask at hal[0x58]; sent verbatim as AQ_PHY_OPS payload:**

| Name | Bit | fw byte/bit | Description |
|------|-----|-------------|-------------|
| `AQ_ADV_100M` | 0 | fw[0x10].0 | Advertise 100 Mbps |
| `AQ_ADV_1G` | 1 | fw[0x10].1 | Advertise 1 Gbps |
| `AQ_ADV_2G5` | 2 | fw[0x10].2 | Advertise 2.5 Gbps |
| `AQ_ADV_5G` | 3 | fw[0x10].3 | Advertise 5 Gbps |
| `AQ_ADV_MASK` | 0x0F | — | Speed advertisement mask |
| `AQ_PAUSE` | 16 | fw[0x12].0 | Pause frame support |
| `AQ_ASYM_PAUSE` | 17 | fw[0x12].1 | Asymmetric pause |
| `AQ_LOW_POWER` | 18 | fw[0x12].2 | Low-power mode |
| `AQ_PHY_POWER_EN` | 19 | fw[0x12].3 | PHY power enable |
| `AQ_WOL` | 20 | fw[0x12].4 | Wake-on-LAN |
| `AQ_DOWNSHIFT` | 21 | fw[0x12].5 | Speed downshift enable |
| `AQ_DSH_RETRIES` | 24–27 | fw[0x13].0–3 | Downshift retry count (shift=0x18, mask=0xF000000) |

**WoL flags (AQ_WOL_CFG):** `AQ_WOL_FLAG_MP = 0x2` (magic packet)

`0x21` and `0x32` appear in the binary but lack confirmed names:
- `0x21` — write flash/EEPROM parameter (write counterpart to `AQ_FLASH_PARAMETERS`)
- `0x32` — Clause 45 MDIO read/write (used by `DirectPhyAccess` for PHY register access)

### MAC Register Map (AQ_ACCESS_MAC wValue addresses)

| Addr | Name | Bits / values | Description |
|------|------|---------------|-------------|
| `0x03` | `SFR_GENERAL_STATUS` | — | General device status |
| `0x05` | `SFR_CHIP_STATUS` | — | Chip status |
| `0x0B` | `SFR_RX_CTL` | see below | RX control / packet filter |
| `0x0D` | `SFR_INTER_PACKET_GAP_0` | — | Inter-packet gap |
| `0x10` | `SFR_NODE_ID` | 6 bytes | MAC address |
| `0x16` | `SFR_MULTI_FILTER_ARRY` | 8 bytes | 64-bit multicast hash table |
| `0x22` | `SFR_MEDIUM_STATUS_MODE` | see below | Medium / link mode control |
| `0x24` | `SFR_MONITOR_MODE` | see below | PHY / WoL monitor control |
| `0x26` | `SFR_PHYPWR_RSTCTL` | `0x0010`=BZ, `0x0020`=IPRL | PHY power / reset control |
| `0x2A` | `SFR_VLAN_ID_ADDRESS` | — | VLAN ID address |
| `0x2B` | `SFR_VLAN_ID_CONTROL` | `0x01`=WE, `0x02`=RD, `0x10`=VSO, `0x20`=VFE | VLAN control |
| `0x2C` | `SFR_VLAN_ID_DATA0` | — | VLAN data low |
| `0x2D` | `SFR_VLAN_ID_DATA1` | — | VLAN data high |
| `0x2E` | `SFR_RX_BULKIN_QCTRL` | `0x01`=TIME, `0x02`=IFG, `0x04`=SIZE | Bulk-in queue coalescing control |
| `0x2F` | `SFR_RX_BULKIN_QTIMR_LOW` | — | Queue timer low |
| `0x30` | `SFR_RX_BULKIN_QTIMR_HIGH` | — | Queue timer high |
| `0x31` | `SFR_RX_BULKIN_QSIZE` | — | Queue size threshold |
| `0x32` | `SFR_RX_BULKIN_QIFG` | — | Queue inter-frame gap |
| `0x34` | `SFR_RXCOE_CTL` | `IP`/`TCP`/`UDP`/`ICMP`/`IGMP`/`TCPv6`/`UDPv6`/`ICMPv6` (bits 0–7) | RX checksum offload control |
| `0x35` | `SFR_TXCOE_CTL` | same bit layout as RXCOE | TX checksum offload control |
| `0x41` | `SFR_BM_INT_MASK` | write `0xFF` to unmask all | Burst-mode interrupt mask |
| `0x43` | `SFR_BMRX_DMA_CONTROL` | `0x80`=EN | Burst-mode RX DMA control |
| `0x46` | `SFR_BMTX_DMA_CONTROL` | — | Burst-mode TX DMA control |
| `0x54` | `SFR_PAUSE_WATERLVL_LOW` | — | Pause watermark low |
| `0x55` | `SFR_PAUSE_WATERLVL_HIGH` | — | Pause watermark high |
| `0x9E` | `SFR_ARC_CTRL` | — | ARC control |
| `0xB1` | `SFR_SWP_CTRL` | — | Switch/swap control |
| `0xB2` | `SFR_TX_PAUSE_RESEND_T` | — | TX pause resend timer |
| `0xB7` | `SFR_ETH_MAC_PATH` | `0x01`=RX_PATH_READY | Ethernet MAC path status |
| `0xB9` | `SFR_BULK_OUT_CTRL` | `0x01`=FLUSH_EN, `0x02`=EFF_EN | Bulk-out control |

**SFR_RX_CTL (0x0B) bits:**

| Value | Name | Description |
|-------|------|-------------|
| `0x0000` | `SFR_RX_CTL_STOP` | Stop RX engine |
| `0x0001` | `SFR_RX_CTL_PRO` | Promiscuous mode |
| `0x0002` | `SFR_RX_CTL_AMALL` | Accept all multicast |
| `0x0008` | `SFR_RX_CTL_AB` | Accept broadcast |
| `0x0010` | `SFR_RX_CTL_AM` | Multicast hash filter enable |
| `0x0020` | `SFR_RX_CTL_AP` | Accept all packets |
| `0x0040` | `SFR_RX_CTL_RF_WAK` | Remote wake filter |
| `0x0080` | `SFR_RX_CTL_START` | Start RX engine |
| `0x0100` | `SFR_RX_CTL_DROPCRCERR` | Drop CRC-error frames |
| `0x0200` | `SFR_RX_CTL_IPE` | IP checksum error checking |
| `0x0400` | `SFR_RX_CTL_TXPADCRC` | TX pad and CRC |

Default value in hwSetFilters: `0x0288` = `IPE \| START \| AB`. With hash filter: `0x0298` = adds `AM`.

**SFR_MEDIUM_STATUS_MODE (0x22) bits:**

| Value | Name | Description |
|-------|------|-------------|
| `0x0001` | `SFR_MEDIUM_XGMIIMODE` | XGMII mode (5G/2.5G); else GMII (1G/100M) |
| `0x0002` | `SFR_MEDIUM_FULL_DUPLEX` | Full duplex |
| `0x0010` | `SFR_MEDIUM_RXFLOW_CTRLEN` | RX flow control enable |
| `0x0020` | `SFR_MEDIUM_TXFLOW_CTRLEN` | TX flow control enable |
| `0x0040` | `SFR_MEDIUM_JUMBO_EN` | Jumbo frame enable |
| `0x0100` | `SFR_MEDIUM_RECEIVE_EN` | RX enable — cleared by `hwStop()` |

**SFR_MONITOR_MODE (0x24) bits:** `0x01`=EPHYRW, `0x02`=RWLC, `0x04`=RWMP, `0x08`=RWWF, `0x10`=RW_FLAG, `0x20`=PMEPOL, `0x40`=PMETYPE

### Protocol Pattern

| bRequest | Name | Direction | Description |
|----------|------|-----------|-------------|
| `0x01`   | `AQ_ACCESS_MAC` | IN (0xc0)  | Read MAC register — `wValue` = reg addr, `wLength` = byte count |
| `0x01`   | `AQ_ACCESS_MAC` | OUT (0x40) | Write MAC register — `wValue` = reg addr, `wLength` = byte count, data in buffer |
| `0x20`   | `AQ_FLASH_PARAMETERS` | IN (0xc0) | Read flash/EEPROM — firmware version, MAC address |
| `0x31`   | `AQ_PHY_POWER` | OUT (0x40) | Direct PHY power byte (DirectPhyAccess) |
| `0x32`   | —  | IN/OUT | Clause 45 MDIO read/write (DirectPhyAccess PHY register access) |
| `0x60`   | `AQ_WOL_CFG` | OUT (0x40) | Wake-on-LAN configuration |
| `0x61`   | `AQ_PHY_OPS` | OUT (0x40) | Firmware PHY control struct, 4 bytes (FWPhyAccess) |

`wIndex` in `AQ_ACCESS_MAC` calls: observed values `0x0002`, `0x0008`, `0x0020` — appears to be a secondary length or bank field, not yet fully understood.



### readPhyValue(uint16_t arg1, uint16_t arg2, uint16_t* out)

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,  // IN | Vendor | Device
    .bRequest      = AQ_MDIO,  // PHY read
    .wValue        = arg1,
    .wIndex        = arg2,
    .wLength       = 0x0002, // 2-byte response → *out
};
```

### writePhyValue(uint16_t arg1, uint16_t arg2, uint16_t value)

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0x40,  // OUT | Vendor | Device
    .bRequest      = AQ_MDIO,  // PHY write
    .wValue        = arg1,
    .wIndex        = arg2,
    .wLength       = 0x0002, // 2 bytes to write
};
// data buffer: value
```

### Read Firmware Version

Response is 3 bytes, little-endian.

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,   // IN | Vendor | Device
    .bRequest      = 0x01,   // read register
    .wValue        = AQ_FW_VER_MAJOR,  // 0xDA — reads 3 bytes: major+minor+rev
    .wIndex        = 0x0003,
    .wLength       = 0x0003, // 3-byte LE firmware version
};
// raw: 0x0003000300da01c0
```

### setMtu

Register 0x0022 bit 6 = jumbo frame enable:

```c
uint16_t read_mtu = usb_read_register(0x0022); // 2 bytes
uint16_t cleared  = read_mtu & 0xffbf;         // clear bit 6
uint16_t set      = read_mtu | 0x0040;         // set bit 6

// hal[0x5c] is the configured MTU (e.g. 0x5ea = 1514 = standard Ethernet)
if (hal[0x5c] < 0x5eb) {
    read_mtu = cleared;  // standard MTU — disable jumbo
} else {
    read_mtu = set;      // jumbo MTU — enable jumbo
}
// then write read_mtu back to register 0x0022
// write command: 0x0002000200220140 (bRequest=AQ_ACCESS_MAC OUT, wValue=0x0022, wLength=2)
```

Then a tiered mapping of hal[0x5c] (MTU) to a buffer size value (written to unknown register, TBD):

```c
uint16_t buf_size;
if      (hal[0x5c] < 0x11a3) buf_size = 0x0810;  // MTU < 4515  (standard Ethernet)
else if (hal[0x5c] < 0x252b) buf_size = 0x1020;  // MTU < 9515  (jumbo tier 1)
else if (hal[0x5c] < 0x30e3) buf_size = 0x1420;  // MTU < 12515 (jumbo tier 2)
else                          buf_size = 0x1a20;  // MTU ≥ 12515 (jumbo tier 3)
// standard MTU 1514 → 0x0810
// written to register 0x0054: raw 0x0002000200540140
```

Register 0x0022 known bits:
- bit 6: jumbo frame enable (set when MTU ≥ 0x5eb)
- bit 8: link/TX enable (cleared in hwStop)

### Read MTU / hwStop — Operation 1 of 2

Reads 2-byte MTU value from register 0x0022. Also used standalone as readMtu.

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,   // IN | Vendor | Device
    .bRequest      = 0x01,   // read register
    .wValue        = 0x0022, // MTU register
    .wIndex        = 0x0002,
    .wLength       = 0x0002, // 2-byte LE MTU value
};
// raw: 0x00020002002201c0
```

### hwStop — Operation 2 of 2

Clear bit 8 of the 2-byte response from operation 1, then write back:

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0x40,   // OUT | Vendor | Device
    .bRequest      = 0x01,   // unknown (write register?)
    .wValue        = 0x0022, // same register as operation 1
    .wIndex        = 0x0002,
    .wLength       = 0x0002, // 2 bytes to write
};
// data: (response_from_op1 & ~(1 << 8))
// raw: 0x0002000200220140
```

Pattern: read-modify-write on MTU register 0x0022. Clearing bit 8 likely disables link/TX.

### Set MAC Address

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0x40,   // OUT | Vendor | Device
    .bRequest      = 0x01,   // write register
    .wValue        = 0x0010, // register address
    .wIndex        = 0x0006,
    .wLength       = 0x0006, // 6-byte MAC address
};
// raw: 0x0006000600100140
```

Note: uses generic write register (bRequest=AQ_ACCESS_MAC), unlike read which uses dedicated bRequest=AQ_FLASH_PARAMETERS.
Likely writes to operational/current MAC register, while read returns value from EEPROM.

### Read Permanent MAC Address

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,   // IN | Vendor | Device
    .bRequest      = AQ_FLASH_PARAMETERS,
    .wValue        = 0x0000,
    .wIndex        = 0x0000,
    .wLength       = 0x0006, // 6-byte MAC address response
};
// timeout = 0x2710 = 10000ms
// response: 6 bytes = permanent MAC address
```

## StandardUSB::DeviceRequest

Standard USB setup packet, 8 bytes, matches USB spec wire layout.

```c
struct DeviceRequest {
    uint8_t  bmRequestType;  // direction, type, recipient
    uint8_t  bRequest;       // vendor command ID
    uint16_t wValue;
    uint16_t wIndex;
    uint16_t wLength;        // length of data stage
};
```

## PhyAccess Classes

Two polymorphic PHY accessor classes selected by firmware major version (hal[0x40]):
- `firmware_major < 0x80` → `DirectPhyAccess` — direct USB vendor commands to PHY registers
- `firmware_major >= 0x80` → `FWPhyAccess` — single firmware control struct, firmware mediates PHY

Both are allocated `new(0x14)` (0x14 bytes) in `UsbHal::start()`.

### Vtable layout (identical offsets for both classes)

Object layout (both): `[0x00]` vtable*, `[0x08]` AqUsbHal*, `[0x10..0x13]` FWPhyAccess state (FW only).

| vtable offset | Method | Called from |
|---------------|--------|-------------|
| 0x00 | `~PhyAccess()` (non-deleting) | |
| 0x08 | `~PhyAccess()` (deleting) | |
| 0x10 | `phyPower(bool on)` | `UsbHal::start()` → `phyPower(true)` (power on PHY after pipe setup) |
| 0x18 | `lowPower(bool on)` | (power management path, not traced fully) |
| 0x20 | `advertise(MediumFlags&)` | `AqUsbHal::hwStart()` — configure speed advertisement |
| 0x28 | `sleep(bool sleep)` | `AqUsbHal::enable()` WoL path → `sleep(false)` (wake from WoL) |

### AqUsbHal::vendorCmd(AqUsbHal*, uint8_t cmd, int dir, uint16_t wValue, uint16_t wIndex, uint16_t wLength, void* data)

Internal helper used by both PhyAccess classes. Builds a `StandardUSB::DeviceRequest` and calls `IOUSBHostInterface::deviceRequest` (vtable[0xa98], timeout=10s):

```c
bmRequestType = (dir != 0) ? 0xc0 : 0x40;  // IN or OUT | Vendor | Device
bRequest      = cmd;
wValue        = wValue;
wIndex        = wIndex;
wLength       = wLength;
```

### DirectPhyAccess

#### phyPower(bool on)

New vendor command `bRequest=AQ_PHY_POWER` — direct PHY power control:

```c
uint8_t data = on ? 0x02 : 0x00;
vendorCmd(hal, /*cmd=*/AQ_PHY_POWER, /*OUT*/0, /*wValue=*/0, /*wIndex=*/0, /*wLength=*/1, &data);
if (!on) IOSleep(200);   // 200ms delay on power-down
```

#### lowPower(bool on)

Read-modify-write Clause 22 PHY register 0x1e (via `readPhyValue`/`writePhyValue`, bRequest=AQ_MDIO):

```c
uint16_t val;
readPhyValue(hal, /*arg1=*/0, /*reg=*/0x1e, &val);
val = on ? (val | 0x8000) : (val & 0x7fff);  // bit 15 = power-down
writePhyValue(hal, 0, 0x1e, &val);
```

#### advertise(MediumFlags&)

Programs Clause 45 PHY registers for multi-rate speed advertisement. All calls via `writePhyValue`/`readPhyValue` (bRequest=AQ_MDIO, wValue=devad, wIndex=regaddr):

```c
// MMD device 7 (Auto-Negotiation) registers:
writePhyValue(hal, /*devad=*/7, /*reg=*/0x0000, {0x2000});  // clear standard AN advert
writePhyValue(hal, 7, 0xc400, {0x9c53});  // 2.5G/5G BASE-T advertisement bits
writePhyValue(hal, 7, 0x0020, {0x0181});  // MMD7 extended advertisement

uint16_t val;
readPhyValue(hal, 7, 0x0010, &val);
writePhyValue(hal, 7, 0x0010, {val | 0x0c00});  // set additional capability bits

writePhyValue(hal, 7, 0x0000, {0x3200});  // restart auto-negotiation with multi-rate

// MMD device 0x1e (Aquantia vendor-specific) registers:
writePhyValue(hal, 0x1e, 0xc430, {0x400f});
writePhyValue(hal, 0x1e, 0xc431, {0x4060});
writePhyValue(hal, 0x1e, 0xc432, {0x8000});
```

Register 0x07 = IEEE Clause 45 device 7 (AN MMD); registers 0xc400/0xc431/0xc432 are Aquantia-proprietary extensions for 2.5G/5G advertisement. PHY registers accessed via USB vendor command 0x32 (firmware translates to MDIO).

#### sleep(bool)

No-op — returns `true` immediately. `DirectPhyAccess` does not implement sleep/wake (handled by `phyPower`).

---

### FWPhyAccess

All operations modify a 4-byte control struct at `fw[0x10..0x13]` then send it atomically via a single firmware command:

```c
// bRequest=AQ_PHY_OPS, OUT, wValue=0, wIndex=0, wLength=4, data=fw[0x10..0x13]
vendorCmd(hal, /*cmd=*/AQ_PHY_OPS, /*OUT*/0, 0, 0, /*len=*/4, &fw[0x10]);
```

The 4-byte payload is the **MediumFlags dword sent verbatim** (little-endian). Each method RMWs the relevant bit(s) in the locally-held `fw[0x10..0x13]` copy before sending all 4 bytes to firmware.

Bit layout mapping (MediumFlags → fw struct byte offsets):

| MediumFlags bit | Constant | fw byte | bit | Set by |
|----------------|----------|---------|-----|--------|
| 0  | `AQ_ADV_100M`     | fw[0x10] | 0 | `advertise()` |
| 1  | `AQ_ADV_1G`       | fw[0x10] | 1 | `advertise()` |
| 2  | `AQ_ADV_2G5`      | fw[0x10] | 2 | `advertise()` |
| 3  | `AQ_ADV_5G`       | fw[0x10] | 3 | `advertise()` |
| 16 | `AQ_PAUSE`        | fw[0x12] | 0 | `advertise()` |
| 17 | `AQ_ASYM_PAUSE`   | fw[0x12] | 1 | `advertise()` |
| 18 | `AQ_LOW_POWER`    | fw[0x12] | 2 | `lowPower(bool)` |
| 19 | `AQ_PHY_POWER_EN` | fw[0x12] | 3 | `phyPower(bool)` |
| 20 | `AQ_WOL`          | fw[0x12] | 4 | `sleep(bool)` / WoL path |
| 21 | `AQ_DOWNSHIFT`    | fw[0x12] | 5 | `advertise()` |
| 24-27 | `AQ_DSH_RETRIES` | fw[0x13] | 0-3 | `advertise()` — downshift retry count |

`fw[0x13]` bits[3:0] = `0x07` observed as default downshift retries in `advertise()`.

FWPhyAccess persists this struct in the object so each call is a RMW; no field is ever reconstructed from scratch.

### Vendor commands discovered via PhyAccess

| bRequest | Dir | wValue | wIndex | wLength | Description |
|----------|-----|--------|--------|---------|-------------|
| `0x31`   | OUT | `0x0000` | `0x0000` | 1 | `DirectPhyAccess`: PHY power — data `0x02`=on, `0x00`=off |
| `0x32`   | OUT | devad  | regaddr | 2 | `DirectPhyAccess`: write Clause 45 PHY register |
| `0x32`   | IN  | devad  | regaddr | 2 | `DirectPhyAccess`: read Clause 45 PHY register |
| `0x61`   | OUT | `0x0000` | `0x0000` | 4 | `FWPhyAccess`: write 4-byte firmware control struct |

## IOService vtable (as seen by driver)

| Offset | Symbol |
|--------|--------|
| 0xa98  | `IOUSBHostInterface::deviceRequest(StandardUSB::DeviceRequest& request, void* dataBuffer, IOUSBHostCompletion* completion, unsigned int timeout)` |

## Medium Class

Size: 0x10 bytes

| Offset | Field |
|--------|-------|
| 0x00   | `OSDictionary*` — supported media types, populated via forSpeed() calls (see below) |
| 0x08   | `os_log_t` (class-specific log handle from `_os_log_create`) |

### forSpeed() — Supported Media Types

```c
// forSpeed(this, medium_id, speed_mbps, flag, index, name)
forSpeed(this, 0x20, 0,    0x0f, 0, "Auto");
forSpeed(this, 0x26, 100,  0x01, 1, "100BaseTX-Full");
forSpeed(this, 0x30, 1000, 0x02, 2, "1000BaseT-Full");
forSpeed(this, 0x36, 2500, 0x04, 3, "2500BaseT-Full");  // 0x9c4 = 2500
forSpeed(this, 0x37, 5000, 0x08, 4, "5000BaseT-Full");
```

Each call registers two `IONetworkMedium` entries in the dictionary:

```c
// Base entry
IONetworkMedium* m = IONetworkMedium::medium(medium_id | 0x100000, speed_mbps, flag, index, name);
IONetworkMedium::addMedium((OSDictionary*)this[0x00], m);
m->release();  // vtable+0x28

// Flow Control entry
strlcat(name, "-FC", 0x28);
m = IONetworkMedium::medium(medium_id | 0x500000, speed_mbps, flag | 0x30, index + 5, name);
IONetworkMedium::addMedium((OSDictionary*)this[0x00], m);
m->release();
```

- `0x100000` — base medium type flag
- `0x500000` — flow control medium type flag (`0x100000 | 0x400000`)
- `flag | 0x30` — adds flow control capability bits
- `index + 5` — FC entries occupy indices 5–9

## Itr Class (Interrupt)

Size: 0x28 bytes

| Offset | Field |
|--------|-------|
| 0x08   | `AqUsbHal*` — back-pointer to HAL |
| 0x18   | `void*` — context/entry passed as `context` arg to `performUrb()` |
| 0x20   | `IOMemoryDescriptor*` — interrupt receive buffer |

### Itr::start()

Posts a single pre-posted interrupt IN URB. One outstanding URB at a time (no ring).

```c
AqUsbHal::performUrb(itr[0x08], To=ITR, itr[0x18], itr[0x20], /*size=*/8);
return 1;
```

### Itr::onItrComplete(void* context, int status, unsigned int bytes)

URB completion handler — re-posts URB and dispatches link status.

```c
if (status != 0) return;   // error — drop silently, do NOT re-post

AqUsbHal::onInterruptEvent(itr[0x08], itr[0x18]);   // process 8-byte ItrData

// Tail-call: re-post the same interrupt URB to keep it running
performUrb(itr[0x08], To=ITR, itr[0x18], itr[0x20], 8);
```

### Interrupt dispatch chain

```
IOUSBHostPipe completion
  → onCompleteAction<AqUsbHal, &AqUsbHal::onItrComplete>()
  → AqUsbHal::onItrComplete(ctx, status, bytes)
       if hal[0x44]==0: return   // not enabled, drop
       load hal[0x00] (driver*)
       → AqPacificDriver::onItrComplete(driver, status, bytes)
           load driver[0x160] (Itr*)
           → Itr::onItrComplete(itr, status, bytes)    // see above
```

### ItrData layout (8 bytes, filled by interrupt IN URB)

The first two bytes form a 16-bit little-endian status word:

| Field | Mask | Description |
|-------|------|-------------|
| Link status | `0x8000` (bit 15) | 1 = link up, 0 = link down |
| Speed code | `0x7F00` >> 8 | Speed identifier (see table below) |
| Flow control | byte[2] bits[1:0] | Active flow control (3 = TX+RX) |

Speed codes (byte[1] & 0x7F, i.e. bits 14:8 of status word):

| Speed code | Speed | ItrData[1] |
|-----------|-------|------------|
| `0x0F` | 5 Gbps | `0x8F` |
| `0x10` | 2.5 Gbps | `0x90` |
| `0x11` | 1 Gbps | `0x91` |
| `0x13` | 100 Mbps | `0x93` |

`hal[0x43]` caches `ItrData[1]` for change detection.

### AqUsbHal::onInterruptEvent(AqUsbHal* hal, ItrData* data)

```c
if (data[1] == hal[0x43]) return;   // no link state change — early exit

hal[0x43] = data[1];                // cache new state

uint16_t status = *(uint16_t*)data;
bool up         = (status & 0x8000) != 0;         // link status bit
uint8_t speed   = (status & 0x7F00) >> 8;         // speed code

// Compiler used add-0x71-and-wrap trick to map speed codes to table indices:
//   0x0F→0 (5G), 0x10→1 (2.5G), 0x11→2 (1G), 0x13→4 (100M)
uint8_t idx = (uint8_t)(data[1] + 0x71);
uint32_t speed_mbps   = (idx <= 4) ? speed_table[idx]  : 0;  // 0x3fa0
uint32_t medium_index = (idx <= 4) ? medium_table[idx] : 0;  // 0x3fc0

hwOnLinkChange(hal, data, speed_mbps);   // program hardware for new speed

// Flow control: if both TX+RX active, use FC variant of medium
uint32_t link = medium_index;
if ((data[2] & 3) == 3) link = medium_index + 5;

AqPacificDriver::onLinkStatusChanged(driver, link, up);   // tail-call
```

Speed/medium tables (5 × uint32_t each):

| idx | speed_mbps | medium_index | speed code | ItrData[1] |
|-----|-----------|--------------|------------|------------|
| 0   | 5000      | 4            | `0x0F`     | `0x8F`     |
| 1   | 2500      | 3            | `0x10`     | `0x90`     |
| 2   | 1000      | 2            | `0x11`     | `0x91`     |
| 3   | 0         | 0            | —          | `0x92` (unused?) |
| 4   | 100       | 1            | `0x93`           |

### AqUsbHal::hwOnLinkChange(AqUsbHal* hal, ItrData* data, uint32_t speed_mbps)

Programs hardware registers for the new link speed. Only entered when `data[1] < 0` (link up, bit 7 set — link down path skips straight to return at 0x17dd).

Register write sequence on link-up (via `IOUSBHostInterface::deviceRequest`, vtable[0xa98], timeout=10s):

| Register | Name | Bytes | Notes |
|----------|------|-------|-------|
| `0x000d` | `SFR_INTER_PACKET_GAP_0` | 1 | `0x05` if 5G, else `0x00` |
| `0x00b2` | `SFR_TX_PAUSE_RESEND_T` | 3 | speed-dependent 3-byte value |
| `0x002e`–`0x0032` | `SFR_RX_BULKIN_QCTRL`… | 5 | RX coalescing config (see table below) |
| `0x000b` | `SFR_RX_CTL` | 2 | written to `0x0000` (`SFR_RX_CTL_STOP`) |
| `0x00b7` | `SFR_ETH_MAC_PATH` | 1 | written to `1` (`SFR_RX_PATH_READY`) |
| `0x00b9` | `SFR_BULK_OUT_CTRL` | 1 | written to `2` (`SFR_BULK_OUT_EFF_EN`) |
| `0x0022` | `SFR_MEDIUM_STATUS_MODE` | 2 | RMW — set speed/duplex/flow-control/jumbo bits |
| `0x0022` | `SFR_MEDIUM_STATUS_MODE` | 2 | second write — set `SFR_MEDIUM_RECEIVE_EN` |
| `0x002b` | `SFR_VLAN_ID_CONTROL` | 1 | written to `0x10` (`SFR_VLAN_CONTROL_VSO`) |
| `0x0046` | `SFR_BMTX_DMA_CONTROL` | 1 | speed-dependent |
| `0x009e` | `SFR_ARC_CTRL` | 1 | speed-dependent |
| `0x000b` | `SFR_RX_CTL` | 2 | second write — re-enable RX with filter bits |

**RX bulk-in coalescing configuration** (written to `SFR_RX_BULKIN_QCTRL`..`SFR_RX_BULKIN_QIFG`, 5 bytes):

| Profile | ctrl | timer_l | timer_h | size | ifg | Used for |
|---------|------|---------|---------|------|-----|----------|
| High speed | `0x07` | `0x00` | `0x01` | `0x1E` | `0xFF` | 5G / 2.5G / 1G |
| 100M | `0x07` | `0xA0` | `0x00` | `0x14` | `0x00` | 100 Mbps |
| Jumbo | `0x07` | `0x00` | `0x01` | `0x18` | `0xFF` | Jumbo MTU |

`ctrl=0x07` = `SFR_RX_BULKIN_QCTRL_TIME | SFR_RX_BULKIN_QCTRL_IFG | SFR_RX_BULKIN_QCTRL_SIZE` (all coalescing modes active). Timer is 16-bit LE across `QTIMR_LOW`/`QTIMR_HIGH`. High-speed profile uses a longer timer (0x0100) and larger size threshold (30 frames) vs 100M (shorter timer 0x00A0, 20 frames, no IFG coalescing).

### AqPacificDriver::onLinkStatusChanged(AqPacificDriver* drv, uint32_t link_medium_idx, bool up)

```c
driver[0x148] = up;   // store link-up flag

if (up) {
    IONetworkMedium* medium = OSDictionary_lookup(driver[0x130], link_medium_idx);
    // esi = kIONetworkLinkValid | kIONetworkLinkActive = 3, edx = medium*
} else {
    medium = null;
    // esi = kIONetworkLinkValid = 1, edx = null
}

// vtable[0x980] on driver = setLinkStatus(state, medium, speed=0, ...)
driver->vtable[0x980](esi, medium, 0, 0);  // → IONetworkInterface::setLinkStatus
```

Additional driver ivars discovered:
- `driver[0x148]` = `uint8_t` link-up flag (1=up, 0=down)



## Rx Class

Size: 0x30 bytes

| Offset | Field |
|--------|-------|
| 0x10   | `RxRing*` — pointer to ring buffer descriptor (see layout below) |
| 0x18   | `AqUsbHal*` — back-pointer to HAL, used to call `performUrb()` |
| 0x20   | `AqPacificDriver*` — back-pointer to driver, used in `clean()` for `onInputPacket()` |

### RxRing layout

Ring of 10 slots, each **0xb5 bytes**. Preceded by two DWORDs:

| Offset | Field |
|--------|-------|
| `ring[0x00]` | DWORD: head index — next slot to consume in `clean()` |
| `ring[0x04]` | DWORD: fill index — next slot to post in `refill()` |
| `ring[8 + n*0xb5 + 0x00]` | mbuf chain pointer |
| `ring[8 + n*0xb5 + 0x08]` | `IOMemoryDescriptor*` |
| `ring[8 + n*0xb5 + 0xb0]` | DWORD: state (zeroed on init and after processing) |
| `ring[8 + n*0xb5 + 0xb4]` | byte: flag |
| `ring[8 + n*0xb5 + 0xb8]` | DWORD: transfer status / byte count (written by URB completion) |
| `ring[8 + n*0xb5 + 0xbc]` | byte: completion flag — non-zero = URB complete, ready to process |

### Rx::start()

Calls `Rx::refill()` and returns 1.

### Rx::refill()

Pre-posts bulk IN URBs to fill the RX ring. Also called from `Rx::service()` after completions.

```
available = ring->capacity - ring->fill_index
if available < 2: return  // ring sufficiently full

for each available slot (up to 10 total):
    allocate mbuf pair
    map mbuf data via IOMemoryDescriptor::withAddress(ptr, len, 0x101, kernel_task)
    entry[0x08] = mem_desc
    mem_desc->vtable[0x1f0]()              // prepare / map descriptor
    AqUsbHal::performUrb(hal, To=RX, entry, mem_desc, 0x10000)
    if performUrb fails: release mem_desc, break
    ring->fill_index = (fill_index + 1) % 10
```

### Rx::service(void*)

Called on URB completion (interrupt context). Calls `Rx::clean()` then tail-calls `Rx::refill()`.

### RX Bulk IN Buffer Layout

Each 64KB bulk IN URB receives a variable-length buffer structured as:

```
[4-byte RX Descriptor Header]
[packet 0: 2-byte HW pad + payload]
[packet 1: 2-byte HW pad + payload]
...
[packet N-1: 2-byte HW pad + payload]
[N × 8-byte RX Packet Descriptors]   ← at byte offset desc_offset from buffer start
```

**RX Descriptor Header** (first 4 bytes of buffer):

| Bits | Mask | Description |
|------|------|-------------|
| 12:0 | `0x1FFF` | Packet count — number of packets in this transfer |
| 31:13 | `0xFFFFE000` >> 13 | Descriptor offset — byte offset to the packet descriptor array |

**RX Packet Descriptor** (8 bytes per packet, at desc_offset):

| Bits | Description |
|------|-------------|
| 0 | L4 checksum error |
| 1 | L3 checksum error |
| 4:2 | L4 type: `0x04`=UDP, `0x10`=TCP |
| 6:5 | L3 type: `0x20`=IPv4, `0x40`=IPv6 |
| 10 | VLAN tag present |
| 11 | RX OK — packet received without errors |
| 30:16 | Packet length (mask `0x7FFF0000` >> 16) |
| 31 | Drop — discard this packet |
| 63:32 | VLAN tag (16-bit 802.1Q tag, shift `0x20`) |

`AQ_RX_HW_PAD = 0x02` — 2-byte pad prepended by hardware to each packet to align the IP header to a 4-byte boundary within the buffer.

### Rx::clean()

Drains all completed ring entries and delivers packets to the network stack.

```
while ring[head*0xb5 + 0xbc] != 0:   // completion flag set
    entry = ring[head]
    memdesc = entry[0x08]
    memdesc->vtable[0x1f8]()           // complete / unmap descriptor

    // Parse RX Descriptor Header from start of buffer
    uint32_t header = *(uint32_t*)buffer;
    pkt_count   = header & 0x1FFF;          // number of packets
    desc_offset = (header & 0xFFFFE000) >> 13;  // offset to descriptor array

    if pkt_count == 0: skip (drop)

    // Walk each packet using its RX Packet Descriptor
    for i in range(pkt_count):
        uint64_t pd = *(uint64_t*)(buffer + desc_offset + i*8);
        if pd & AQ_RX_PD_DROP: continue
        if !(pd & AQ_RX_PD_RX_OK): continue
        pkt_len = (pd & 0x7FFF0000) >> 16;

        mbuf = entry[0x00]
        if mbuf != null:
            Rx::setChecksum(mbuf, pd)           // apply HW checksum offload info
            if pd & AQ_RX_PD_VLAN: set VLAN tag on mbuf from pd[63:32]
            AqPacificDriver::onInputPacket(driver, mbuf, pkt_len - 2, 1, 0)
                                                // -2 for AQ_RX_HW_PAD

    ring->head = (head + 1) % 10
    release IOMemoryDescriptor (vtable[0x28])
    clear entry[0x00], entry[0x08], entry[0xb0], entry[0xbc]

AqPacificDriver::flushInputQueue()      // flush batch to network stack
```

## Tx Class

Size: 0x30 bytes

| Offset | Field |
|--------|-------|
| 0x10   | `TxRing*` — pointer to TX ring descriptor (see layout below) |
| 0x18   | `AqUsbHal*` — back-pointer to HAL, used to call `performUrb()` |
| 0x20   | `AqPacificDriver*` — back-pointer to driver, used for `dequeueOutputPackets()` |

### TxRing layout

Ring of **32 slots** (0x20, wrap mod 0x20). Each entry is **0x18 bytes** (24 bytes). Preceded by two DWORDs:

| Offset | Field |
|--------|-------|
| `ring[0x00]` | DWORD: head index — next slot to free in `onComplete()` |
| `ring[0x04]` | DWORD: fill index — next slot to use in `transmit()` |
| `ring[8 + n*0x18 + 0x00]` | pre-allocated DMA/bounce buffer ptr — allocated during `init()`, one 0x4000-byte region per slot |
| `ring[8 + n*0x18 + 0x08]` | `IOMemoryDescriptor*` — per-frame descriptor, created by `withAddressRanges()` in `transmit()` |
| `ring[8 + n*0x18 + 0x10]` | `__mbuf*` — mbuf being transmitted; released in `onComplete()` |

`init()` pre-allocates 32 × 0x4000-byte (16 KB) DMA buffers and stores them in entry[0x00]. Confirms TX ring is separate from free-list allocation; entries are recycled in-place.

### TX Packet Descriptor

An 8-byte header prepended to each outgoing packet at the start of the 16 KB DMA buffer, before the payload:

| Bits | Description |
|------|-------------|
| 20:0 | Packet byte length (mask `0x1FFFFF`) |
| 28 | Drop padding — strip pad bytes before transmit |
| 29 | VLAN tag present — 802.1Q tag in bits 63:48 |
| 46:32 | MSS — TCP segment size for firmware TSO (15 bits, shift `0x20`) |
| 63:48 | VLAN tag — 16-bit 802.1Q tag (shift `0x30`) |

The length field covers the payload only. MSS non-zero signals the device to perform TCP segmentation offload in firmware.

### Tx::start()

One-liner — returns 1 immediately (no URBs pre-posted; TX is demand-driven).

### Tx::transmit(__mbuf*)

Called from `AqPacificDriver::outputPacket(__mbuf*, void*)` and `AqPacificDriver::outputStart(IONetworkInterface*, unsigned int)`.

```c
// Return codes (stored in retval throughout):
//   0 = success / keep sending
//   1 = no ring space (TX ring full)
//   2 = IOMemoryDescriptor alloc failed

TxRing* ring = tx[0x10];

// Check available ring space: head - fill + 32 (mod 32)
uint32_t available = (ring->head - ring->fill + 0x20) % 0x20;
if (available < 2) return 1;   // ring full

TxEntry* entry = &ring->entries[ring->fill];

// Build scatter-gather list from mbuf chain
// (stack-local array of { ptr, len } pairs, each 0x10 bytes, max 29 entries)
uint32_t total_len = 0;
uint32_t sg_count  = 0;
bool fits_in_slot  = true;     // r13b
__mbuf* seg = mbuf;
while (seg != null) {
    uintptr_t seg_data = mbuf_data(seg);
    uint32_t  seg_len  = mbuf_len(seg);
    if (fits_in_slot) {
        uint32_t so_far = total_bytes_in_current_slot + seg_len;
        if (so_far > 0x4000) {        // segment crosses 16 KB slot boundary
            fits_in_slot = false;     // fall to scatter path
        }
    }
    if (!fits_in_slot) {
        // append to SG list entry (scatter across pre-alloc slot)
        sg_list[sg_count] = { seg_data + offset_in_slot, seg_len };
        total_len += seg_len;
    } else {
        if (sg_count >= 0x1d) break;  // max 29 SG entries
        sg_list[sg_count++] = { seg_data, seg_len };
        total_len += seg_len;
    }
    seg = mbuf_next(seg);
}

// Build frame header (packet count + some metadata) into entry's DMA buffer slot
// (RMW of a DWORD in the pre-alloc buffer region; embeds mbuf_pkthdr_len bits)

// Fetch VLAN tag if present
uint16_t vlan_tag = 0;
mbuf_get_vlan_tag(mbuf, &vlan_tag_flags, &vlan_tag);
if (vlan_tag_flags != 0) {
    entry->dma_buf[3] |= 0x20;        // set VLAN present flag in header
    entry->dma_buf[6] = vlan_tag & 0x7fff;
}

// Create IOMemoryDescriptor over the SG list (mbuf data in-place, no copy)
IOMemoryDescriptor* memdesc = IOMemoryDescriptor::withAddressRanges(sg_list, sg_count, 0, kernel_task);
if (memdesc == null) {
    mbuf_freem(mbuf);
    return 2;
}
entry->memdesc = memdesc;
entry->mbuf    = dequeued_mbuf;

// Map descriptor for DMA
memdesc->vtable[0x1f0](memdesc, 0);  // prepare()

// Advance fill index (wrap at 32)
ring->fill = (ring->fill + 1) % 0x20;

// Submit USB bulk OUT URB
AqUsbHal::performUrb(tx[0x18], To=TX, entry, memdesc, total_len);

// Continue loop while ring has space (ja 0x36b8)
return 0;
```

### Tx::onComplete(void* entry)

Called from `AqPacificDriver::onTransmitComplete()` on URB completion.

```c
// Unmap and release the per-frame IOMemoryDescriptor
IOMemoryDescriptor* memdesc = entry[0x08];
memdesc->vtable[0x1f8](memdesc, 0);  // complete() / unmap
memdesc->vtable[0x28](memdesc);      // release()
entry[0x08] = null;

// Release the transmitted mbuf
mbuf_freem(entry[0x10]);
entry[0x10] = null;

// Advance head (wrap at 32)
TxRing* ring = tx[0x10];
ring->head = (ring->head + 1) % 0x20;

// Notify driver that TX queue slot freed — tail-call
AqPacificDriver::onUnstallTxQueue(tx[0x20]);
```

### Tx::service(void*)

One-liner — returns immediately (no-op; TX is completion-driven via `onComplete()`).

## UsbHal Class

Size: 0x60 bytes

| Offset | Field |
|--------|-------|
| 0x00   | `driver*` (back pointer to parent driver object) |
| 0x08   | `IOUSBHostInterface*` (stored in UsbHal::start after safeMetaCast of provider) |
| 0x10   | `IOUSBHostDevice*` — parent device, obtained via `hal[0x08]->getDevice()` in UsbHal::start |
| 0x18   | `os_log_t` (HAL-specific log handle from `_os_log_create`) |
| 0x20   | `IOUSBHostPipe*` bulk IN — RX pipe (EP2 IN Bulk 1024B), opened in findEnpoints() |
| 0x28   | `IOUSBHostPipe*` bulk OUT — TX pipe (EP3 OUT Bulk 1024B), opened in findEnpoints() |
| 0x30   | `IOUSBHostPipe*` interrupt IN — status pipe (EP1 IN Interrupt 16B), opened in findEnpoints() |
| 0x38   | `DirectPhyAccess*` or `FWPhyAccess*` (0x14 bytes) — polymorphic PHY accessor; selected by firmware major version: < 0x80 → `DirectPhyAccess` (direct USB vendor cmds), >= 0x80 → `FWPhyAccess` (firmware-mediated); `(*obj)[0x20]()` called during enable() |
| 0x40   | `uint8_t[3]` firmware version (3 bytes LE, read via bRequest=AQ_ACCESS_MAC wValue=AQ_FW_VER_MAJOR during UsbHal::start) |
| 0x43   | (gap/padding) |
| 0x44   | `uint8_t` enabled flag (set to 1 in UsbHal::enable(), both WoL and normal paths) |
| 0x45   | `uint8_t[6]` MAC address (read from EEPROM via bRequest=AQ_FLASH_PARAMETERS during enable) |
| 0x4b   | `uint8_t` reconfigured flag (set to 1 if setConfiguration(1) was called during UsbHal::start) |
| 0x4c   | `uint8_t` multicast filter active flag (cleared when list > 0x40 entries) |
| 0x4d   | `uint8_t` promiscuous mode flag |
| 0x4e   | `uint8_t[8]` multicast hash filter bitmap — 64-bit hash table, see algorithm below |
| 0x56   | `uint8_t` all-multicast flag (set to 1 when multicast list > 0x40 entries) |
| 0x57   | `uint8_t` (suspected wake-on-magic-packet flag) |
| 0x58   | `uint32_t` MediumFlags — 32-bit bitmask; default lower byte `0x0f` (AQ_ADV_MASK, all speeds); upper bits control PAUSE/LOW_POWER/PHY_POWER_EN/WOL/DOWNSHIFT; sent verbatim as 4-byte AQ_PHY_OPS payload |
| 0x5c   | `uint32_t` (MTU, value 0x5ea = 1514 = standard Ethernet MTU) |

### Multicast Hash Filter Algorithm

Standard CRC32 hash, applied per MAC address in the list (≤ 0x40 entries):

```c
// For each IOEthernetAddress in list:
uint32_t crc = 0xffffffff;
for (int i = 0; i < 6; i++) {
    uint8_t b = addr.bytes[i];
    for (int bit = 0; bit < 8; bit++) {
        uint32_t msb = crc >> 31;
        crc <<= 1;
        if ((b & 1) != msb)
            crc ^= 0x04C11DB7;  // standard Ethernet CRC32 polynomial
        b >>= 1;
    }
}
// Top 6 bits of CRC select one of 64 positions in the 8-byte hash table:
uint8_t byte_idx = crc >> 29;          // bits 31:29 → byte 0-7 within hal[0x4e..0x55]
uint8_t bit_idx  = (crc >> 26) & 0x7; // bits 28:26 → bit 0-7 within that byte
hal[0x4e + byte_idx] |= (1 << bit_idx);
```

After processing all entries: `hal[0x4c] = 1` (multicast filter active).

Note: fields 0x44–0x58 appear unaligned — suspected packed USB vendor command/packet structure laid out on-wire. TODO: correlate with AQC111 vendor command spec.

---

## AsyncThreadObject Class

Base class shared by `Rx` and `Tx`. Wraps a kernel `thread_call_t` to allow deferred work items to be scheduled off interrupt context.

Size: 0x10 bytes

| Offset | Field |
|--------|-------|
| 0x00   | `vtable*` |
| 0x08   | `thread_call_t` — allocated in constructor |

### Vtable

| Slot     | Method |
|----------|--------|
| vtable[0x10] | `schedule()` |
| vtable[0x18] | `cancel()` |
| vtable[0x20] | `run()` → `jmp vtable[0x28]` (abstract dispatch) |
| vtable[0x28] | `service()` — abstract; overridden by `Rx` and `Tx` |

### Constructor

```c
// thread_call_allocate_with_options(func, param, pri, flags)
self[0x08] = thread_call_allocate_with_options(run_fn, self, 0, 1);
```

`run_fn` is a static trampoline: `AsyncThreadObject::run(thread_call_param_t param0, thread_call_param_t param1)` — ignores both params, casts `param0` back to `AsyncThreadObject*` and tail-calls `vtable[0x28]` (`service()`).

### schedule()

```c
thread_call_enter(self[0x08]);
```

Called from `Rx::onRxComplete()` (completion callback, interrupt context) to defer `Rx::service()` onto a kernel thread.

Also called from `Tx::onComplete()` indirectly via `onUnstallTxQueue()`.

### cancel()

```c
thread_call_cancel(self[0x08]);
```

Called during teardown (`Rx::stop()`, `Tx::stop()`).

### Abort detection in completion callbacks

Before calling `schedule()`, completion callbacks check the URB status:
```c
if (status == 0xe00002eb)   // kIOReturnAborted
    return;                 // do not reschedule; teardown in progress
```

### DriverKit note

DriverKit has dispatch queues (`IODispatchQueue`) — `AsyncThreadObject` is **not** needed. Rx/Tx completion blocks run on the driver's dispatch queue by default. Use `ivars->queue->DispatchAsync(^{ ... })` to defer work if needed.

---

## Teardown Chain

Teardown is triggered by USB device removal or OS shutdown. The call sequence is:

```
disable() → willTerminate() → didTerminate() → stop()
```

### AqPacificDriver::disable(IONetworkInterface*)

```c
// 1. Stop output queue (no more outputPacket calls)
IOOutputQueue* q = getOutputQueue();
q->vtable[0x130](q);        // IOOutputQueue::stop()

// 2. Stop output thread
stopOutputThread(interface, 0);

// 3. Abort interrupt pipe (prevents new status callbacks)
Itr::stop(driver[0x160]);   // → abortUrb(ITR=2)
driver[0x148] = 0;          // clear Itr active flag

// 4. Stop RX (abort bulk IN pipe)
Rx::stop(driver[0x158]);    // → abortUrb(RX=1); ring->head = 0

// 5. Disable HAL (stop hardware, mark disabled)
AqUsbHal::disable(driver[0x120], interface);
```

### AqUsbHal::disable(IONetworkInterface*)

```c
hal[0x44] = 0;   // clear enabled flag
hal[0x43] = 0;   // clear last ItrData[1] (link speed cache)

if (wol_active)
    hwPrepareSleep();   // WoL path — configure wake filters
else
    hwStop();           // normal path
```

### AqUsbHal::hwStop()

```c
// 1. Read-modify-write register 0x0022: clear bit 8 (TX/link enable)
uint16_t reg22;
vendorCmd_read(bRequest=AQ_ACCESS_MAC, wValue=0x0022, wIndex=0x0002, data=&reg22, len=2);
reg22 &= ~0x0100;   // clear bit 8 (byte[1] bit 0)
vendorCmd_write(bRequest=AQ_ACCESS_MAC, wValue=0x0022, wIndex=0x0002, data=&reg22, len=2);

// 2. Withdraw speed advertisements (PHY stops trying to link)
uint8_t zero = 0;
phy->advertise(&zero);   // PhyAccess::advertise — vtable[0x20]

// 3. Put PHY into low-power mode
phy->lowPower(true);     // PhyAccess::lowPower — vtable[0x18]
```

Register 0x0022 is one of the initialization registers written during `hwStart()`. Bit 8 appears to be a TX/link-enable flag; clearing it quiesces the device-side data path before withdrawing the PHY advertisement.

The `vendorCmd_read`/`vendorCmd_write` here both use `bRequest=AQ_ACCESS_MAC` (bulk register access, same as hwSetFilters), not the single-register `bRequest=AQ_FLASH_PARAMETERS`/`0x21` form used by `readReg`/`writeReg`.

### AqPacificDriver::willTerminate(IOService* provider, IOOptionBits options)

```c
// Abort pending RX and interrupt URBs so they don't fire after provider gone
Rx::stop(driver[0x158]);    // abortUrb(RX=1)
abortUrb(ITR=2);            // abort interrupt pipe directly

// Tail-call super
super::willTerminate(provider, options);   // [vtable dispatch]
```

### AqPacificDriver::didTerminate(IOService* provider, IOOptionBits options, bool* defer)

```c
AqUsbHal::stop(driver[0x120]);
*defer = false;   // (implicit — returns true/kIOReturnSuccess)
```

### AqPacificDriver::stop(IOService* provider)

```c
Tx::stop(driver[0x150]);         // release all TxRing memdesc + mbuf
AqUsbHal::stop(driver[0x120]);   // release pipes, close interface, destroy PhyAccess
detachInterface(driver[0x118], false);
super::stop(provider);           // [tail call via vtable]
```

### AqUsbHal::stop()

```c
if (!hal[0x4b]) {        // not reconfigured
    phy->phyPower(false); // power down PHY
}
delete hal[0x38];        // destroy PhyAccess object (DirectPhyAccess or FWPhyAccess)
hal[0x38] = nullptr;

// Release the three pipes (vtable[0x28] = release/retain/free)
if (hal[0x20]) { hal[0x20]->vtable[0x28](hal[0x20]); hal[0x20] = nullptr; }  // RX bulk IN
if (hal[0x28]) { hal[0x28]->vtable[0x28](hal[0x28]); hal[0x28] = nullptr; }  // TX bulk OUT
if (hal[0x30]) { hal[0x30]->vtable[0x28](hal[0x30]); hal[0x30] = nullptr; }  // ITR interrupt IN

// Close the USB interface
hal[0x08]->vtable[0x5d8](hal[0x08]);   // IOUSBHostInterface::close()
```

### AqUsbHal::abortUrb(To direction)

```c
// direction: 1=RX (bulk IN), 2=ITR (interrupt IN), 3=TX (bulk OUT)
IOUSBHostPipe* pipe = (direction == 1) ? hal[0x20]
                    : (direction == 2) ? hal[0x30]
                    :                    hal[0x28];

if (pipe == nullptr) return;

// IOUSBHostPipe::abort(IOUSBHostPipe*, uint32_t options, IOReturn withError, uint32_t forEndpointVariant)
pipe->vtable[0x178](pipe, 0, 0xe00002eb /*kIOReturnAborted*/, 0);
```

Aborting causes all outstanding URBs on that pipe to complete with `kIOReturnAborted`. Completion callbacks detect this and skip rescheduling (see AsyncThreadObject abort detection above).

### Itr::stop()

```c
abortUrb(ITR=2);
```

One-liner. The ITR pipe abort causes the pending interrupt IN URB to complete with `kIOReturnAborted`; `onItrComplete` detects and returns without resubmitting.

### Rx::stop()

```c
abortUrb(RX=1);
ring->head = 0;   // reset ring head pointer
```

Outstanding bulk IN URBs complete with `kIOReturnAborted`; `onRxComplete` detects abort status and does not call `schedule()`.

### Tx::stop()

```c
// Walk all 32 ring slots, release any in-flight resources
TxRing* ring = tx[0x10];
for (int i = 0; i < 0x20; i++) {
    TxRingEntry* entry = &ring->entries[i];
    if (entry->memdesc != nullptr) {
        entry->memdesc->complete();
        entry->memdesc->release();
        entry->memdesc = nullptr;
    }
    if (entry->mbuf != nullptr) {
        freePacket(entry->mbuf);
        entry->mbuf = nullptr;
    }
}
```

Note: `abortUrb(TX)` is NOT called in `Tx::stop()` directly — TX URBs are aborted implicitly when the pipe is released in `AqUsbHal::stop()`.

---

## Exported Functions — Coverage Status

Functions exported (symbolicated) in the binary. ✅ = documented above. ⬜ = not yet documented.

| Symbol | Status |
|--------|--------|
| `AqPacificDriver::start(IOService*)` | ✅ |
| `AqPacificDriver::stop(IOService*)` | ✅ |
| `AqPacificDriver::disable(IONetworkInterface*)` | ✅ |
| `AqPacificDriver::willTerminate(IOService*, uint)` | ✅ |
| `AqPacificDriver::didTerminate(IOService*, uint, bool*)` | ✅ |
| `AqPacificDriver::enable(IONetworkInterface*)` | ✅ |
| `AqPacificDriver::outputStart(IONetworkInterface*, uint)` | ✅ |
| `AqPacificDriver::outputPacket(mbuf_t, void*)` | ✅ (brief) |
| `AqPacificDriver::onLinkStatusChanged(...)` | ✅ |
| `AqPacificDriver::onUnstallTxQueue(AqPacificDriver*)` | ✅ |
| `AqUsbHal::start(IOService*)` | ✅ |
| `AqUsbHal::stop()` | ✅ |
| `AqUsbHal::enable(IONetworkInterface*)` | ✅ |
| `AqUsbHal::disable(IONetworkInterface*)` | ✅ |
| `AqUsbHal::hwStart()` | ✅ |
| `AqUsbHal::hwStop()` | ✅ |
| `AqUsbHal::hwOnLinkChange(uint8_t)` | ✅ |
| `AqUsbHal::hwPrepareSleep()` | ⬜ (WoL path, lower priority) |
| `AqUsbHal::hwFinishSleep()` | ⬜ (WoL path, lower priority) |
| `AqUsbHal::hwSetFilters()` | ⬜ (writes multicast/promisc registers) |
| `AqUsbHal::findEnpoints()` | ✅ |
| `AqUsbHal::abortUrb(To)` | ✅ |
| `AqUsbHal::onInterruptEvent(...)` | ✅ |
| `AqUsbHal::performUrb(...)` | ✅ |
| `AqUsbHal::vendorCmd(...)` | ✅ |
| `AqUsbHal::readReg(uint16_t)` | ✅ |
| `AqUsbHal::writeReg(uint16_t, uint16_t)` | ✅ |
| `Tx::start()` | ✅ |
| `Tx::stop()` | ✅ |
| `Tx::transmit(mbuf_t)` | ✅ |
| `Tx::onComplete(...)` | ✅ |
| `Tx::service(void*)` | ✅ |
| `Rx::start()` | ✅ |
| `Rx::stop()` | ✅ |
| `Rx::service(void*)` | ✅ |
| `Rx::onRxComplete(...)` | ✅ |
| `Itr::start()` | ✅ |
| `Itr::stop()` | ✅ |
| `Itr::onItrComplete(...)` | ✅ |
| `DirectPhyAccess::phyPower(bool)` | ✅ |
| `DirectPhyAccess::lowPower(bool)` | ✅ |
| `DirectPhyAccess::advertise(uint8_t*)` | ✅ |
| `DirectPhyAccess::sleep(bool)` | ✅ |
| `FWPhyAccess::phyPower(bool)` | ✅ |
| `FWPhyAccess::lowPower(bool)` | ✅ |
| `FWPhyAccess::advertise(uint8_t*)` | ✅ |
| `FWPhyAccess::sleep(bool)` | ✅ |
| `AqPacificDriver::selectMedium(IONetworkMedium const*)` | ✅ |
| `AqPacificDriver::setPromiscuousMode(bool)` | ✅ |
| `AqPacificDriver::setMulticastMode(bool)` | ✅ |
| `AqPacificDriver::setMulticastList(IOEthernetAddress*, uint32_t)` | ✅ |
| `AqPacificDriver::setWakeOnMagicPacket(bool)` | ✅ |
| `AqPacificDriver::setMaxPacketSize(uint32_t)` | ✅ |

---

## RX Filter, Multicast, and Medium Selection

### AqPacificDriver — driver-level stubs

All five methods are single-line stubs: load `driver[0x120]` (HAL pointer) into `rdi`, forward the same argument, tail-call the HAL method, return 0.

```c
AqPacificDriver::setMulticastMode(bool on)     → AqUsbHal::setMulticast(on)
AqPacificDriver::setPromiscuousMode(bool on)   → AqUsbHal::setPromiscuous(on)
AqPacificDriver::setMulticastList(addr, count) → AqUsbHal::setMulticastList(addr, count)
AqPacificDriver::setWakeOnMagicPacket(bool on) → AqUsbHal::setWakeOnMagicPacket(on)
AqPacificDriver::setMaxPacketSize(uint32_t n)  → AqUsbHal::setMtu(n)
```

`selectMedium` does slightly more (see below).

### AqUsbHal::setMulticast(bool on)

```c
hal[0x4c] = on;   // multicast filter active flag
hwSetFilters();
```

### AqUsbHal::setPromiscuous(bool on)

```c
hal[0x4d] = on;   // promiscuous mode flag
hwSetFilters();
```

### AqUsbHal::setWakeOnMagicPacket(bool on)

```c
hal[0x57] = on;   // WoL flag — stored but NOT forwarded to hwSetFilters here;
                  // used by hwPrepareSleep() when suspending
```

### AqUsbHal::setMtu(uint32_t n)

```c
hal[0x5c] = n - 4;   // store MTU minus 4 (strips FCS from IOKit-provided value)
onMtuChanged();       // sends MTU to device
```

### AqUsbHal::setMulticastList(IOEthernetAddress* list, uint32_t count)

```c
if (count > 0x40) {
    // Too many entries for hash filter — switch to all-multicast
    hal[0x56] = 1;    // all-multicast flag
    hal[0x4c] = 0;    // disable hash filter
    memset(hal[0x4e], 0, 8);  // clear hash table
} else {
    // Compute CRC32 per address, accumulate 64-bit hash table
    // (same algorithm as Multicast Hash Filter Algorithm section above)
    hal[0x4c] = 1;    // hash filter active
}
hwSetFilters();
```

### AqUsbHal::hwSetFilters()

Called after any filter state change. Guards on `hal[0x43] != 0` (device link active); returns immediately if the device is not yet linked.

```c
if (hal[0x43] == 0) return;   // no link yet — skip

// Build the 2-byte RX filter mode word
uint16_t filter = 0x0288;     // default: unicast + broadcast + directed multicast

if (hal[0x4c]) {
    // Hash multicast filter enabled — upload 8-byte hash table first
    filter = 0x0298;           // bit[4] set = hash filter enable
    vendorCmd(bRequest=AQ_ACCESS_MAC, wValue=0x0016, wIndex=0x0008,
              data=&hal[0x4e], len=8);   // write multicast hash table
}
if (hal[0x4d]) filter |= 0x01;   // bit[0] = promiscuous
if (hal[0x56]) filter |= 0x02;   // bit[1] = all-multicast

// Write RX filter mode register
vendorCmd(bRequest=AQ_ACCESS_MAC, wValue=0x000b, wIndex=0x0020,
          data=&filter, len=2);
```

Filter mode bits (register at wValue=0x000b):
| Bit | Meaning |
|-----|---------|
| 0   | Promiscuous mode |
| 1   | All-multicast (receive all multicast frames) |
| 4   | Multicast hash filter enable (use 64-bit hash table at wValue=0x0016) |

Vendor command bRequest=AQ_ACCESS_MAC is a bulk register write (distinct from bRequest=0x21 single-register write).

Also called from `hwOnLinkChange()` after link-up, to re-apply filter state on each link event.

### AqPacificDriver::selectMedium(IONetworkMedium const* medium)

```c
if (medium != nullptr) {
    // Retrieve the medium's type/flags (vtable[0x130] on IONetworkMedium)
    uint32_t flags = medium->getMediumFlags();
    // Update HAL speed advertisement
    AqUsbHal::setLinkSpeed(hal, &flags);
}
// Always update the current medium (regardless of null)
IONetworkController::setCurrentMedium(this, medium);   // vtable[0x978]
return kIOReturnSuccess;
```

### AqUsbHal::setLinkSpeed(MediumFlags* flags)

```c
hal[0x58] = *flags;   // update MediumFlags byte

if (hal[0x44] == 0) return;   // not yet enabled — skip advertise
                               // (speeds will be advertised at hwStart time)

// Re-advertise if already enabled
phy->advertise(&hal[0x58]);   // PhyAccess::advertise — vtable[0x20]
```

This allows runtime speed changes (e.g., user forces 1G in Network preferences) to take effect immediately without a full restart.

---

## Checksum Offload

### AqPacificDriver::getChecksumSupport(uint32_t* checksumMask, uint32_t checksumFamily, bool isOutput)

Address: `0x2b7e` (kext binary).

```c
if (checksumFamily != kChecksumFamilyInet) {
    return kIOReturnUnsupported;
}
*checksumMask |= 0x67;   // kChecksumIP | kChecksumTCP | kChecksumUDP |
                         //   kChecksumTCPIPv6 | kChecksumUDPIPv6
return kIOReturnSuccess;
```

The same mask `0x67` is returned for both TX (`isOutput=true`) and RX (`isOutput=false`). The `isOutput` parameter is not checked — behaviour is identical for both directions.

IOKit checksum capability flags (IOChecksumFamily / IOChecksumOperation):

| Value  | Constant            | Meaning               |
|--------|---------------------|-----------------------|
| `0x01` | `kChecksumIP`       | IPv4 header checksum  |
| `0x02` | `kChecksumTCP`      | TCP over IPv4         |
| `0x04` | `kChecksumUDP`      | UDP over IPv4         |
| `0x20` | `kChecksumTCPIPv6`  | TCP over IPv6         |
| `0x40` | `kChecksumUDPIPv6`  | UDP over IPv6         |

Sum: `0x01|0x02|0x04|0x20|0x40 = 0x67`.

Note: ICMP (`kChecksumICMP`) and ICMPv6 are supported by the hardware SFR (`SFR_RXCOE_CTL` bits 3,7) but are **not** advertised here and not verified in software. The kext does not touch ICMP checksum status. **DriverKit impl: skip ICMP offload** — ICMP traffic volume is negligible and the original vendor didn't bother; not worth the complexity.

---

### Rx::setChecksum(__mbuf* mbuf, uint64_t rx_pd)

Address: `0x22e4` (kext binary). Called from `Rx::clean()` for every received packet.

The lower 16 bits of the RX packet descriptor (`rx_pd & 0xFFFF`) encode L3/L4 type and error status:

| Bits | Field       | Meaning                                        |
|------|-------------|------------------------------------------------|
| 1:0  | `L4_ERR`, `L3_ERR` | Checksum error flags (1 = error detected) |
| 4:2  | L4 type     | `1`=UDP, `4`=TCP, others=unknown/not checked   |
| 6:5  | L3 type     | `1`=IPv4, `2`=IPv6                             |

Logic (pseudocode):

```c
uint16_t pd16 = rx_pd & 0xFFFF;
bool     L3_ERR = (pd16 >> 1) & 1;
bool     L4_ERR = (pd16 >> 0) & 1;
uint8_t  l4_type = (pd16 >> 2) & 7;   // 1=UDP, 4=TCP
uint8_t  l3_type = (pd16 >> 5) & 3;   // 1=IPv4, 2=IPv6
bool     is_ipv6 = (l3_type == 2);

uint32_t checked = 0, valid = 0;

if (l3_type == 1 /* IPv4 */) {
    checked |= kChecksumIP;              // 0x01
    if (!L3_ERR) valid |= kChecksumIP;
}

if (l4_type == 1 /* UDP */) {
    uint32_t bit = is_ipv6 ? kChecksumUDPIPv6 : kChecksumUDP;   // 0x40 or 0x04
    checked |= bit;
    if (!L4_ERR) valid |= bit;
} else if (l4_type == 4 /* TCP */) {
    uint32_t bit = is_ipv6 ? kChecksumTCPIPv6 : kChecksumTCP;   // 0x20 or 0x02
    checked |= bit;
    if (!L4_ERR) valid |= bit;
}

// vtable[0x960] on the controller object
setChecksumResult(mbuf, kChecksumFamilyInet, checked, valid, 0, 0);
```

`checked` is the set of checksums the hardware examined; `valid` is the subset that passed. The IOKit stack uses this to skip software re-verification of valid checksums.

IPv6 IP-header checksum (`kChecksumIP`) is never added to `checked` for IPv6 frames — correct, since IPv6 has no header checksum.


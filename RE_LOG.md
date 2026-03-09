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

Contains the full hardware init sequence (to be documented):
- reads permanent MAC (bRequest=0x20) → stores in hal[0x45]
- writes MAC to register 0x0010
- write 0xff to register 0x0041
- write 0x00 to register 0x00b1
- RMW register 0x0024: val &= 0xe0
- RMW register 0x000b: if (val & 0x80) val &= 0x7f
- RMW register 0x0022: if (val & 0x0100) val &= 0xfeff
- RMW register 0x00b0: if (val & 0x01) val &= 0xfe
- if (hal[0x38] != null) → call hal[0x38]->vtable[0x20]()  // PhyAccess callback

### AqUsbHal::performUrb(To, void* context, IOMemoryDescriptor*, unsigned int size)

Submits an async USB I/O request on the appropriate pipe.

```c
enum To { TX = 0, RX = 1, ITR = 2 };

if (hal[0x44] == 0) return kIOReturnNotOpen;   // not enabled

switch (direction) {
    case TX:   pipe = hal[0x28]; callback = AqUsbHal::onTransmitComplete; break;
    case RX:   pipe = hal[0x20]; callback = AqUsbHal::onReceiveComplete;  break;
    case ITR:  pipe = hal[0x30]; callback = AqUsbHal::onItrComplete;      break;
    default:   pipe = null; callback = null; break;
}

// Build IOUSBHostCompletion on stack: { owner=hal, action=callback, parameter=context }
// Submit:
pipe->vtable[0x258](pipe, memdesc, size, &completion, 0);
// vtable[0x258] = IOUSBHostPipe::io(IOMemoryDescriptor*, uint32_t length,
//                                   IOUSBHostCompletion*, uint32_t timeout)
```

Callers:
- `Rx::refill()` — `performUrb(RX, entry, memdesc, 0x10000)`
- `Itr::start()` — `performUrb(ITR, entry, memdesc, 8)`
- `Tx::transmit(__mbuf*)` — `performUrb(TX, entry, memdesc, len)`

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

### hwStop

## Vendor Commands

### Protocol Pattern

| bRequest | Direction | Description |
|----------|-----------|-------------|
| `0x01`   | IN (0xc0)  | Read register — `wValue` = register address, `wLength` = byte count |
| `0x01`   | OUT (0x40) | Write register — `wValue` = register address, `wLength` = byte count, data in buffer |
| `0x20`   | IN (0xc0)  | Read permanent MAC address from EEPROM — returns 6 bytes |

`wIndex` observed values: `0x0001`, `0x0002`, `0x0003` — purpose unknown, may indicate register bank or endpoint.
| `0x32`   | IN (0xc0)  | Read PHY value — `wValue` = arg1, `wIndex` = arg2, returns 2 bytes |
| `0x32`   | OUT (0x40) | Write PHY value — `wValue` = arg1, `wIndex` = arg2, sends 2 bytes |

`wIndex` purpose unknown — observed values: `0x0002`, `0x0003`.



### readPhyValue(uint16_t arg1, uint16_t arg2, uint16_t* out)

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,  // IN | Vendor | Device
    .bRequest      = 0x32,  // PHY read
    .wValue        = arg1,
    .wIndex        = arg2,
    .wLength       = 0x0002, // 2-byte response → *out
};
```

### writePhyValue(uint16_t arg1, uint16_t arg2, uint16_t value)

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0x40,  // OUT | Vendor | Device
    .bRequest      = 0x32,  // PHY write
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
    .wValue        = 0x00da, // register address
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
// write command: 0x0002000200220140 (bRequest=0x01 OUT, wValue=0x0022, wLength=2)
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

Note: uses generic write register (bRequest=0x01), unlike read which uses dedicated bRequest=0x20.
Likely writes to operational/current MAC register, while read returns value from EEPROM.

### Read Permanent MAC Address

```c
StandardUSB::DeviceRequest req = {
    .bmRequestType = 0xc0,   // IN | Vendor | Device
    .bRequest      = 0x20,   // 32 — read MAC command
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

Completion: `AqUsbHal::onItrComplete(void*, void*, int, unsigned int)` — re-posts URB and dispatches link status change.



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

### Rx::clean()

Drains all completed ring entries and delivers packets to the network stack.

```
while ring[head*0xb5 + 0xbc] != 0:   // completion flag set
    entry = ring[head]
    memdesc = entry[0x10]
    memdesc->vtable[0x1f8]()           // complete / unmap descriptor

    parse RX_PACKET_DESC from entry[0xb8]:
        pkt_len   = status & 0x1fff    // bits [12:0] = ethernet frame length
        pkt_count = status >> 0xd      // bits [31:13] = number of frames

    if pkt_len == 0: skip (drop)

    mbuf = entry[0x00]
    if mbuf != null:
        alloc new mbuf of size (pkt_len + 7) & 0x7ff8  // aligned
        Rx::setChecksum(mbuf, RX_PACKET_DESC&)          // apply HW checksum offload
        if flag & 4: set VLAN tag on mbuf
        AqPacificDriver::onInputPacket(driver, mbuf, pkt_len - header_offset - 2, 1, 0)
                                        // deliver to IONetworkInterface

    ring->head = (head + 1) % 10
    release IOMemoryDescriptor (vtable[0x28])
    clear entry[0x00], entry[0x08], entry[0xb0], entry[0xbc]

AqPacificDriver::flushInputQueue()      // flush batch to network stack
```

## Tx Class

Size: 0x30 bytes

| Offset | Field |
|--------|-------|

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
| 0x40   | `uint8_t[3]` firmware version (3 bytes LE, read via bRequest=0x01 wValue=0x00da during UsbHal::start) |
| 0x43   | (gap/padding) |
| 0x44   | `uint8_t` enabled flag (set to 1 in UsbHal::enable(), both WoL and normal paths) |
| 0x45   | `uint8_t[6]` MAC address (read from EEPROM via bRequest=0x20 during enable) |
| 0x4b   | `uint8_t` reconfigured flag (set to 1 if setConfiguration(1) was called during UsbHal::start) |
| 0x4c   | `uint8_t` multicast filter active flag (cleared when list > 0x40 entries) |
| 0x4d   | `uint8_t` promiscuous mode flag |
| 0x4e   | `uint8_t[8]` multicast hash filter bitmap — 64-bit hash table, see algorithm below |
| 0x56   | `uint8_t` all-multicast flag (set to 1 when multicast list > 0x40 entries) |
| 0x57   | `uint8_t` (suspected wake-on-magic-packet flag) |
| 0x58   | `uint8_t` (unknown, observed value: 0xc0) |
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


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

### enable(IONetworkInterface*)

Standard `IOEthernetController` override — called when interface is brought up.

```
1. UsbHal::enable():
   if (hal[0x57] != 0):
       call hal[0x28]()   // WoL enable handler
   else:
       read 6-byte permanent MAC (bRequest=0x20) → store in hal[0x45]
       write MAC to register 0x0010 (setMacAddress)
       write 0xff to register 0x0041 (1 byte) — suspected packet filter / RX enable
       write 0x00 to register 0x00b1 (1 byte)
       RMW register 0x0024: val &= 0xe0 (unconditional, clears bits [4:0])
       RMW register 0x000b: if (val & 0x80) val &= 0x7f
       RMW register 0x0022: if (val & 0x0100) val &= 0xfeff (disable link/TX if enabled)
       RMW register 0x00b0: if (val & 0x01) val &= 0xfe
       if (hal[0x38] != null) → call (*hal[0x38])[0x20]()  // delegate callback
   hal[0x44] = 1   // enabled flag, set in both paths
2. IONetworkInterface::startOutputThread(interface)  // start TX output thread
3. <TODO: intermediate steps>
4. Rx::enable()
5. Itr::enable()
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

## Rx Class

Size: 0x30 bytes

| Offset | Field |
|--------|-------|

## Tx Class

Size: 0x30 bytes

| Offset | Field |
|--------|-------|

## UsbHal Class

Size: 0x60 bytes

| Offset | Field |
|--------|-------|
| 0x00   | `driver*` (back pointer to parent driver object) |
| 0x18   | `os_log_t` (HAL-specific log handle from `_os_log_create`) |
| 0x28   | `fn_ptr` — function pointer, called from driver enable() when hal[0x57] (WoL flag) is non-zero |
| 0x38   | `void*` — pointer to an object with function pointers; if non-null, `(*obj)[0x20]()` is called during enable() and hwStop. Delegate/callback interface. |
| 0x44   | `uint8_t` enabled flag (set to 1 in UsbHal::enable(), both WoL and normal paths) |
| 0x45   | `uint8_t[6]` MAC address (read from EEPROM via bRequest=0x20 during enable) |
| 0x4b   | `uint8_t` (unknown) |
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


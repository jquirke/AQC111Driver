
//  AQC111NIC.cpp
//  AQC111 — Personality B: USB Ethernet NIC
//
//  Provider is IOUSBHostInterface (Config 1, bInterfaceClass=255).
//  Config 1 is already pinned by Personality A (AQC111) which holds the
//  device session open. We receive the interface nub directly as provider.
//
//  Start() flow:
//    1. super::Start(provider, SUPERDISPATCH)
//    2. Cast provider to IOUSBHostInterface
//    3. CopyDevice() — device ref for control transfers
//    4. Open device (adds our ref; helps pin Config 1 if A tears down first)
//    5. Open interface
//    6. Read MAC, write to SFR_NODE_ID
//    7. CopyPipe × 3, ClearStall
//    8. Networking queues + RegisterEthernetInterface
//    9. Post AsyncIO (10×RX, 1×ITR)
//   10. RegisterService, schedule timer diagnostic
//

#include <os/log.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <DriverKit/DriverKit.h>
#include <USBDriverKit/USBDriverKit.h>
#include <NetworkingDriverKit/NetworkingDriverKit.h>

#include "AQC111NIC.h"

// Log levels — DriverKit's os_log only exposes OS_LOG_TYPE_DEFAULT (no
// os_log_debug/info/subsystem-category API like userspace macOS os_log), so
// verbosity filtering happens here rather than via the OS logging system.
// gLogLevel defaults to Info and can be raised via the "AQC111LogLevel"
// personality property (load-time, see Start()) or live via IOUserClient.
// See IMPL_PLAN.md "Log Level Strategy".
#define kLogLevelError      0
#define kLogLevelInfo       1
#define kLogLevelDebug      2
#define kLogLevelVerbose    3
static volatile uint8_t gLogLevel = kLogLevelInfo;

#define LogE(fmt, ...) do { if (gLogLevel >= kLogLevelError)   os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] Error(level=%u) - " fmt,   gLogLevel, ##__VA_ARGS__); } while (0)
#define LogI(fmt, ...) do { if (gLogLevel >= kLogLevelInfo)    os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] Info(level=%u) - " fmt,    gLogLevel, ##__VA_ARGS__); } while (0)
#define LogD(fmt, ...) do { if (gLogLevel >= kLogLevelDebug)   os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] Debug(level=%u) - " fmt,   gLogLevel, ##__VA_ARGS__); } while (0)
#define LogV(fmt, ...) do { if (gLogLevel >= kLogLevelVerbose) os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] Verbose(level=%u) - " fmt, gLogLevel, ##__VA_ARGS__); } while (0)

extern "C" kern_return_t
AQC111SetNICLogLevel(uint32_t level)
{
    if (level > kLogLevelVerbose) {
        return kIOReturnBadArgument;
    }
    gLogLevel = (uint8_t)level;
    os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] - log level set to %u (0=Error 1=Info 2=Debug 3=Verbose)", level);
    return kIOReturnSuccess;
}

extern "C" uint32_t
AQC111GetNICLogLevel(void)
{
    return gLogLevel;
}

// Shared by the load-time read (Start() via CopyProperties) and any future
// property-based path — looks up "AQC111LogLevel" in the given dictionary and
// applies it to gLogLevel if present and valid.
static void
applyLogLevelFromDictionary(OSDictionary *dict)
{
    if (dict == nullptr) {
        return;
    }
    OSNumber *num = OSDynamicCast(OSNumber, dict->getObject("AQC111LogLevel"));
    if (num == nullptr) {
        return;
    }
    uint32_t level = num->unsigned32BitValue();
    if (level <= kLogLevelVerbose) {
        gLogLevel = (uint8_t)level;
    }
}

// Endpoint addresses for Config 1 vendor interface (class 0xFF)
#define EP_ITR  0x81   // EP1 IN  Interrupt 16B  — link status
#define EP_RX   0x82   // EP2 IN  Bulk 1024B     — receive
#define EP_TX   0x03   // EP3 OUT Bulk 1024B     — transmit

// RX ring — 10 outstanding USB bulk IN transfers, each 64KB.
// Device aggregates multiple Ethernet frames per transfer.
#define RX_SLOTS        10
#define RX_BUF_SIZE     0x10000   // 64KB per slot

#define AQC111_MIN_MTU          1500
#define AQC111_MAX_MTU          16334
#define AQC111_ETH_HEADER_LEN   14
#define AQC111_VLAN_TAG_LEN     4   // 802.1Q tag (see IMPL_PLAN.md M6e)
#define AQC111_TX_DESC_LEN      8
#define AQC111_MAX_FRAME_LEN    (AQC111_MAX_MTU + AQC111_ETH_HEADER_LEN + AQC111_VLAN_TAG_LEN)

// TSO (IMPL_PLAN.md M10): the stack may hand one oversized TCP packet — up to
// a 65535-byte IP packet (Linux parity, netif_set_tso_max_size) — which the
// device segments into MSS-sized wire frames. Pool buffers and the TX staging
// buffer are sized to hold the largest such packet.
#define AQC111_TSO_MAX_IP_LEN    65535
#define AQC111_TSO_MAX_FRAME_LEN (AQC111_TSO_MAX_IP_LEN + AQC111_ETH_HEADER_LEN + AQC111_VLAN_TAG_LEN)
#define AQC111_TX_BUF_SIZE      (AQC111_TX_DESC_LEN + AQC111_TSO_MAX_FRAME_LEN + 16 /* worst-case padding */)

// TX descriptor TSO MSS field, bits 46:32 (Linux aqc111.h AQ_TX_DESC_MSS_*).
#define AQ_TX_DESC_MSS_MASK     0x7FFFULL
#define AQ_TX_DESC_MSS_SHIFT    32
// Drop-padding flag, bit 28: transfer carries 8 trailing pad bytes the device
// must discard (set when padding would land on a bulk-OUT maxpacket boundary).
#define AQ_TX_DESC_DROP_PADD    (1ULL << 28)
// Bulk OUT endpoint max packet size (SuperSpeed) — the DROP_PADD boundary.
#define AQC111_BULK_OUT_MAXPACKET 1024

// SFR_RXCOE_CTL: per-protocol RX checksum offload enable (see IMPL_PLAN.md M6a).
// TODO: most other SFR register addresses in this file are still raw hex
// literals (e.g. 0x000B, 0x0022, 0x00B7) — refactor to named constants
// incrementally rather than in one large pass.
#define SFR_RXCOE_CTL       0x0034
#define SFR_RXCOE_IP        0x01
#define SFR_RXCOE_TCP       0x02
#define SFR_RXCOE_UDP       0x04
#define SFR_RXCOE_TCPV6     0x20
#define SFR_RXCOE_UDPV6     0x40

// SFR_TXCOE_CTL: same per-protocol bit layout as SFR_RXCOE_CTL, TX direction
// (see IMPL_PLAN.md TX checksum offload). Pure link-level toggle — unlike RX,
// there is no per-packet TX descriptor checksum bit (confirmed against both
// Linux aqc111_tx_fixup and the RE'd x86 TX descriptor layout); once enabled
// the hardware auto-detects and fixes up every outgoing IP/TCP/UDP frame.
#define SFR_TXCOE_CTL       0x0035
#define SFR_TXCOE_IP        0x01
#define SFR_TXCOE_TCP       0x02
#define SFR_TXCOE_UDP       0x04
#define SFR_TXCOE_TCPV6     0x20
#define SFR_TXCOE_UDPV6     0x40

#define AQ_REG_MEDIUM_MODE              0x0022
#define AQ_MEDIUM_XGMII_MODE            0x0001
#define AQ_MEDIUM_FULL_DUPLEX           0x0002
#define AQ_MEDIUM_RX_FLOW_CONTROL       0x0010
#define AQ_MEDIUM_TX_FLOW_CONTROL       0x0020
#define AQ_MEDIUM_JUMBO_FRAME_ENABLE    0x0040
#define AQ_MEDIUM_RECEIVE_ENABLE        0x0100

#define AQ_REG_RX_BULK_QUEUE_CTRL       0x002E
#define AQ_REG_PAUSE_WATERMARK          0x0054
#define AQ_REG_VLAN_CONTROL             0x002B

#define AQ_VLAN_CONTROL_NONE            0x00
#define AQ_VLAN_CONTROL_STRIP_ENABLE    0x10

// Max multicast groups the 64-bucket hash table can represent precisely
// before falling back to accept-all-multicast (matches Linux's AQ_MAX_MCAST
// in aqc111_set_rx_mode). Validated 2026-06-23 with this temporarily lowered
// to 10 — see IMPL_PLAN.md M6h / "Bug fix plan — AMALL fallback...".
#define AQ_MAX_MCAST_ADDRESSES          64

#define AQ_PAUSE_WATERMARK_LOW_BYTE     0
#define AQ_PAUSE_WATERMARK_HIGH_BYTE    1
#define AQ_PAUSE_WATERMARK_LEN          2

#define AQ_RX_BULK_QUEUE_CTRL_TIME      0x01
#define AQ_RX_BULK_QUEUE_CTRL_IFG       0x02
#define AQ_RX_BULK_QUEUE_CTRL_SIZE      0x04
#define AQ_RX_BULK_QUEUE_CTRL_ALL       (AQ_RX_BULK_QUEUE_CTRL_TIME | AQ_RX_BULK_QUEUE_CTRL_IFG | AQ_RX_BULK_QUEUE_CTRL_SIZE)

#define AQ_RX_BULK_COALESCE_CTRL        0
#define AQ_RX_BULK_COALESCE_TIMER_LOW   1
#define AQ_RX_BULK_COALESCE_TIMER_HIGH  2
#define AQ_RX_BULK_COALESCE_SIZE        3
#define AQ_RX_BULK_COALESCE_IFG         4
#define AQ_RX_BULK_COALESCE_LEN         5

// Full hwAssist capability mask this driver declares via getFeatureFlags()
// and self-initializes hwAssistMask to. Shared by both so they can't drift.
#define AQC111_HWASSIST_MASK ( \
    kIOUserNetworkHWAssistRxChecksum | \
    kIOUserNetworkHWAssistTxChecksumIPHdr | \
    kIOUserNetworkHWAssistTxChecksumTCP | \
    kIOUserNetworkHWAssistSoftwareVlan | \
    kIOUserNetworkHWAssistTxChecksumUDP | \
    kIOUserNetworkHWAssistTSO4 | \
    kIOUserNetworkHWAssistTSO6)

// RX Packet Descriptor checksum sub-fields (lower 16 bits of pd; see
// IMPL_PLAN.md M6a — cross-checked against Linux aqc111.h and x86 kext RE).
#define AQ_RX_PD_L4_ERR         0x01
#define AQ_RX_PD_L3_ERR         0x02
#define AQ_RX_PD_L4_TYPE_MASK   0x1C
#define AQ_RX_PD_L4_TYPE_SHIFT  2
#define AQ_RX_PD_L4_UDP         1
#define AQ_RX_PD_L4_TCP         4
#define AQ_RX_PD_L3_TYPE_MASK   0x60
#define AQ_RX_PD_L3_TYPE_SHIFT  5
#define AQ_RX_PD_L3_IPV4        1
#define AQ_RX_PD_L3_IPV6        2

static kern_return_t aqWrite(IOUSBHostInterface *iface, uint16_t addr, const void *data, uint16_t len);
static kern_return_t aqRead(IOUSBHostInterface *iface, uint16_t addr, void *data, uint16_t len);
static kern_return_t aqVendorOut(IOUSBHostInterface *iface, uint8_t request, const void *data, uint16_t len);
static kern_return_t aqWrite16(IOUSBHostInterface *iface, uint16_t addr, uint16_t value);
static kern_return_t aqRead16(IOUSBHostInterface *iface, uint16_t addr, uint16_t *value);
static kern_return_t aqVendorOut32(IOUSBHostInterface *iface, uint8_t request, uint32_t value);
static void disarmAsyncIO(struct AQC111NIC_IVars *ivars);
static void hwDisable(IOUSBHostInterface *iface);
static void hwOnLinkUp(struct AQC111NIC_IVars *ivars, uint8_t speedCode);
static void hwOnLinkDown(IOUSBHostInterface *iface);
static kern_return_t applyMtuToHardware(struct AQC111NIC_IVars *ivars);
static void ensureRxStarted(struct AQC111NIC_IVars *ivars, uint8_t speedCode);
static void ensureRxStopped(struct AQC111NIC_IVars *ivars);
struct RxParseInfo {
    uint32_t descriptorOffset;
    uint32_t packetCount;
};
static bool parseRxLayout(const uint8_t *buf, uint32_t actualByteCount, RxParseInfo *info);
static uint32_t linkSpeedMbps(uint8_t speedCode);

static uint16_t
readLe16(const uint8_t *p)
{
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t
readLe32(const uint8_t *p)
{
    return (uint32_t)p[0] |
        ((uint32_t)p[1] << 8) |
        ((uint32_t)p[2] << 16) |
        ((uint32_t)p[3] << 24);
}

static uint64_t
readLe64(const uint8_t *p)
{
    return (uint64_t)readLe32(p) | ((uint64_t)readLe32(p + 4) << 32);
}

static void
writeLe16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
}

static void
writeLe32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v & 0xFF);
    p[1] = (uint8_t)((v >> 8) & 0xFF);
    p[2] = (uint8_t)((v >> 16) & 0xFF);
    p[3] = (uint8_t)((v >> 24) & 0xFF);
}

static void
writeLe64(uint8_t *p, uint64_t v)
{
    writeLe32(p, (uint32_t)(v & 0xFFFFFFFFULL));
    writeLe32(p + 4, (uint32_t)((v >> 32) & 0xFFFFFFFFULL));
}

// Reads the permanent 6-byte MAC address from device EEPROM via AQ_FLASH_PARAMETERS.
// RE: bmRequestType=0xC0 IN|Vendor|Device, bRequest=0x20, wValue=0, wIndex=0, wLength=6.
static kern_return_t
readMACAddress(IOUSBHostInterface *iface, IOUserNetworkMACAddress *out)
{
    IOBufferMemoryDescriptor *buf = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionIn, 6, 0, &buf);
    if (ret != kIOReturnSuccess) return ret;
    buf->SetLength(6);

    uint16_t transferred = 0;
    ret = iface->DeviceRequest(0xC0, 0x20, 0, 0, 6, buf, &transferred, 10000);
    if (ret == kIOReturnSuccess && transferred == 6) {
        IOAddressSegment range;
        buf->GetAddressRange(&range);
        memcpy(out->octet, (const void *)range.address, 6);
    }
    OSSafeReleaseNULL(buf);
    return ret;
}

static uint32_t
linkSpeedMbps(uint8_t speedCode)
{
    switch (speedCode) {
        case 0x0F: return 5000;
        case 0x10: return 2500;
        case 0x11: return 1000;
        case 0x13: return 100;
        default:   return 0;
    }
}

static uint32_t
clampMtu(uint32_t mtu)
{
    if (mtu < AQC111_MIN_MTU) {
        return AQC111_MIN_MTU;
    }
    if (mtu > AQC111_MAX_MTU) {
        return AQC111_MAX_MTU;
    }
    return mtu;
}

struct AQC111NIC_IVars {
    // M11 phase 0: cumulative SetPowerState counters. Carried in the
    // SetPowerState log line itself so a lost wake-side log still shows up
    // as an incremented on-count in the NEXT sleep's (reliable) Off line.
    uint32_t                            pmOffCount;
    uint32_t                            pmOnCount;
    uint32_t                            pmLowCount;
    uint32_t                            pmOtherCount;
    IODispatchQueue                    *queue;
    IOUserNetworkPacketBufferPool      *pool;
    IOUserNetworkTxSubmissionQueue     *txsQueue;
    IOUserNetworkTxCompletionQueue     *txcQueue;
    IOUserNetworkRxSubmissionQueue     *rxsQueue;
    IOUserNetworkRxCompletionQueue     *rxcQueue;
    IOUSBHostDevice                    *device;
    IOUSBHostInterface                 *interface;
    IOUSBHostPipe                      *pipeItr;
    IOUSBHostPipe                      *pipeRx;
    IOUSBHostPipe                      *pipeTx;
    // RX ring: 10 × 64KB buffers with one outstanding AsyncIO each
    IOBufferMemoryDescriptor           *rxBufs[RX_SLOTS];
    OSAction                           *rxActions[RX_SLOTS];
    // ITR pipe: one 16-byte buffer for link-status interrupt events
    IOBufferMemoryDescriptor           *itrBuf;
    OSAction                           *itrAction;
    uint8_t                             fwMajor;
    uint8_t                             fwMinor;
    uint8_t                             fwRev;
    bool                                lastLinkUp;
    uint8_t                             lastSpeedCode;   // cached from ITR; 0 = never seen
    bool                                interfaceEnabled;
    bool                                rxStarted;
    bool                                ioArmed;
    IOUserNetworkMACAddress             macAddress;
    // PHY advertise mask (AQ_ADV_* bits) applied by hwEnable on every
    // interface-enable. Stored here (not a hwEnable-local literal) so a
    // forced media selection via handleChosenMedia() survives a later
    // ifconfig down/up cycle instead of silently reverting to full
    // autoneg. See IMPL_PLAN.md M6f.
    uint32_t                            phyAdvertiseMask;
    // RX_CTL filter bits beyond the fixed IPE|START|AB base (e.g.
    // SFR_RX_CTL_PRO for promiscuous mode) — stored here, not a hwOnLinkUp-
    // local literal, so the setting survives a later ifconfig down/up cycle
    // instead of silently reverting on the next link-up. See IMPL_PLAN.md M6g.
    uint16_t                            rxFilterBits;
    // SFR_RX_CTL_AMALL has two independent triggers — an explicit
    // SetAllMulticastModeEnable(true) request, and doSetMulticastAddresses()
    // falling back when count exceeds AQ_MAX_MCAST_ADDRESSES. Tracked
    // separately (rather than OR-ing once straight into rxFilterBits) so
    // that when the address count later drops back under the threshold, the
    // overflow contribution can retract on its own without also clearing an
    // independently-active explicit request. recomputeAmallBit() combines
    // both into rxFilterBits. Confirmed reproduced as a real bug before this
    // existed — see IMPL_PLAN.md "Bug fix plan — AMALL fallback...".
    bool                                allMulticastRequested;
    bool                                mcastCountExceeded;
    // Dext-owned queue for OSAction callbacks (USB async IO).
    // CopyDispatchQueue("Default") returns the kernel-side networking proxy queue
    // which doesn't deliver OSAction callbacks into our process.
    IODispatchQueue                    *asyncQueue;
    // TX path — one frame in flight at a time
    IOBufferMemoryDescriptor           *txBuf;           // staging buffer: 8-byte descriptor + frame
    OSAction                           *txPacketAction;  // TxPacketAvailable OSAction
    OSAction                           *txCompleteAction;// OnTxComplete OSAction
    IOUserNetworkPacket                *txInFlight;      // packet held during USB flight
    bool                                txBusy;
    // OS-controlled enable mask (kIOUserNetworkHWAssist* bits), set via
    // SetHardwareAssists. See IMPL_PLAN.md M6a.
    uint32_t                            hwAssistMask;
    uint32_t                            currentMtu;
};

static kern_return_t
setCurrentMtu(AQC111NIC_IVars *ivars, uint32_t requestedMtu, const char *caller)
{
    uint32_t mtu = clampMtu(requestedMtu);

    LogI("%s: requested=%u effective=%u%s", caller, requestedMtu, mtu,
        requestedMtu == mtu ? "" : " (clamped)");

    ivars->currentMtu = mtu;

    if (ivars->interface == nullptr) {
        return kIOReturnSuccess;
    }
    return applyMtuToHardware(ivars);
}

bool
AQC111NIC::init()
{
    if (!super::init()) return false;
    ivars = IONewZero(AQC111NIC_IVars, 1);
    if (ivars == nullptr) return false;
    // Default capenable to everything we advertise via getFeatureFlags() —
    // the OS queries GetHardwareAssists for the *current* enabled set but
    // never calls SetHardwareAssists to turn anything on by default; it only
    // uses that to change state later (e.g. `ifconfig -rxcsum`). Confirmed
    // empirically: SetHardwareAssists never fires during Start(), only
    // GetHardwareAssists. See IMPL_PLAN.md M6a.
    ivars->hwAssistMask = AQC111_HWASSIST_MASK;
    ivars->currentMtu = AQC111_MIN_MTU;
    ivars->phyAdvertiseMask = 0x0000000Fu;  // AQ_ADV_MASK: advertise 100M, 1G, 2.5G, 5G (autoneg all rates)
    return true;
}

void
AQC111NIC::free()
{
    IOSafeDeleteNULL(ivars, AQC111NIC_IVars, 1);
    super::free();
}

kern_return_t
IMPL(AQC111NIC, Start)
{
    kern_return_t ret;
    IOUserNetworkPacketQueue *queues[4];
    struct IOUserNetworkPacketBufferPoolOptions poolOptions;
    IOUserNetworkMACAddress macAddress = {};

    LogI("Start ENTERED: provider=%p", provider);

    ret = Start(provider, SUPERDISPATCH);
    LogI("Start: super -> 0x%x", ret);
    if (ret != kIOReturnSuccess) {
        LogE("Start: super FAILED");
        return ret;
    }
    LogI("Start: super OK");

    {
        OSDictionary *props = nullptr;
        if (CopyProperties(&props) == kIOReturnSuccess && props != nullptr) {
            applyLogLevelFromDictionary(props);
        }
        OSSafeReleaseNULL(props);
        LogI("Start: gLogLevel=%u (0=Error 1=Info 2=Debug 3=Verbose)", gLogLevel);
    }

    // Create a dext-owned queue for Skywalk RxDispatchQueue/TxDispatchQueue slots.
    // IIG's AQC111NIC_QueueNames registers these two names; SetDispatchQueue binds them.
    // "Default" is intentionally NOT overridden — it is a framework-installed proxy queue
    // with hidden internal structure that Stop_Impl's async cancel completion depends on.
    // Replacing "Default" causes a null+0x10 crash in Stop_Impl's teardown block.
    ret = IODispatchQueue::Create("AQC111.async", 0, 0, &ivars->asyncQueue);
    LogI("Start: asyncQueue create -> 0x%x queue=%p", ret, ivars->asyncQueue);
    if (ret != kIOReturnSuccess) goto fail;

    ret = SetDispatchQueue("RxDispatchQueue", ivars->asyncQueue);
    LogI("Start: SetDispatchQueue(RxDispatchQueue) -> 0x%x", ret);
    if (ret != kIOReturnSuccess) goto fail;

    ret = SetDispatchQueue("TxDispatchQueue", ivars->asyncQueue);
    LogI("Start: SetDispatchQueue(TxDispatchQueue) -> 0x%x", ret);
    if (ret != kIOReturnSuccess) goto fail;

    // Provider is IOUSBHostInterface — Config 1, bInterfaceClass=255.
    // Config 1 is already pinned by Personality A (AQC111 device personality).
    ivars->interface = OSDynamicCast(IOUSBHostInterface, provider);
    if (ivars->interface == nullptr) {
        LogI("Start: provider is not IOUSBHostInterface");
        goto fail;
    }

    // Get device for control transfers (bRequest=0x01/0x20/0x61).
    // Personality A already holds it open; we open a second session to
    // ensure Config 1 stays pinned even if A tears down before we do.
    // Get device reference for control transfers. Personality A (AQC111) already
    // holds the exclusive open session; we must NOT call Open() again.
    ret = ivars->interface->CopyDevice(&ivars->device);
    if (ret != kIOReturnSuccess || ivars->device == nullptr) {
        LogE("Start: CopyDevice failed: 0x%x", ret);
        goto fail;
    }
    LogI("Start: CopyDevice OK device=%p", ivars->device);

    // Open our provider interface. No SetConfiguration needed — already done.
    ret = ivars->interface->Open(this, 0, nullptr);
    if (ret != kIOReturnSuccess) {
        LogE("Start: interface Open failed: 0x%x", ret);
        goto fail;
    }
    LogI("Start: interface open");

    // Read permanent MAC address from EEPROM (AQ_FLASH_PARAMETERS, bRequest=0x20).
    {
        kern_return_t macRet = readMACAddress(ivars->interface, &macAddress);
        LogI("Start: readMAC -> 0x%x  %02x:%02x:%02x:%02x:%02x:%02x",
            macRet,
            macAddress.octet[0], macAddress.octet[1], macAddress.octet[2],
            macAddress.octet[3], macAddress.octet[4], macAddress.octet[5]);
        if (macRet != kIOReturnSuccess) {
            macAddress = { .octet = { 0x02, 0xAC, 0x11, 0x11, 0x00, 0x01 } };
        }
        ivars->macAddress = macAddress;

        kern_return_t nodeRet = aqWrite(ivars->interface, 0x0010, ivars->macAddress.octet, 6);
        LogI("Start: write SFR_NODE_ID -> 0x%x", nodeRet);
        uint8_t readback[6] = {};
        kern_return_t rbRet = aqRead(ivars->interface, 0x0010, readback, 6);
        LogI("Start: read  SFR_NODE_ID -> 0x%x  %02x:%02x:%02x:%02x:%02x:%02x",
            rbRet,
            readback[0], readback[1], readback[2],
            readback[3], readback[4], readback[5]);
    }

    // Read firmware version (AQ_FW_VER_MAJOR/MINOR/REV at 0xDA/0xDB/0xDC).
    // major >= 0x80 → FWPhyAccess (AQ_PHY_OPS bRequest=0x61).
    // major <  0x80 → DirectPhyAccess (bRequest=0x31/0x32) — not supported by this driver.
    {
        uint8_t maj = 0, min = 0, rev = 0;
        kern_return_t fr;
        fr = aqRead(ivars->interface, 0xDA, &maj, 1);
        if (fr == kIOReturnSuccess) fr = aqRead(ivars->interface, 0xDB, &min, 1);
        if (fr == kIOReturnSuccess) fr = aqRead(ivars->interface, 0xDC, &rev, 1);
        ivars->fwMajor = maj;
        ivars->fwMinor = min;
        ivars->fwRev   = rev;
        LogI("Start: firmware version %u.%u.%u (major=0x%02x) -> read 0x%x",
            maj, min, rev, maj, fr);
        if (fr != kIOReturnSuccess || (maj & 0x80) == 0) {
            LogE("Start: WARNING — unexpected firmware major=0x%02x; driver requires FWPhyAccess (>= 0x80)", maj);
        }
    }

    ret = ivars->interface->CopyPipe(EP_ITR, &ivars->pipeItr);
    LogI("Start: CopyPipe(ITR) -> 0x%x pipe=%p", ret, ivars->pipeItr);
    if (ret != kIOReturnSuccess || ivars->pipeItr == nullptr) goto fail;

    ret = ivars->interface->CopyPipe(EP_RX, &ivars->pipeRx);
    LogI("Start: CopyPipe(RX)  -> 0x%x pipe=%p", ret, ivars->pipeRx);
    if (ret != kIOReturnSuccess || ivars->pipeRx == nullptr) goto fail;

    ret = ivars->interface->CopyPipe(EP_TX, &ivars->pipeTx);
    LogI("Start: CopyPipe(TX)  -> 0x%x pipe=%p", ret, ivars->pipeTx);
    if (ret != kIOReturnSuccess || ivars->pipeTx == nullptr) goto fail;

    if (ivars->pipeItr) {
        kern_return_t csRet = ivars->pipeItr->ClearStall(false);
        LogI("Start: ClearStall(ITR) -> 0x%x", csRet);
    }
    if (ivars->pipeRx) {
        kern_return_t csRet = ivars->pipeRx->ClearStall(false);
        LogI("Start: ClearStall(RX) -> 0x%x", csRet);
    }

    // --- Networking setup ---

    ret = CopyDispatchQueue("Default", &ivars->queue);
    if (ret != kIOReturnSuccess) {
        LogE("Start: CopyDispatchQueue failed: 0x%x", ret);
        goto fail;
    }

    poolOptions.packetCount = 64;
    poolOptions.bufferCount = 64;
    poolOptions.bufferSize  = AQC111_TSO_MAX_FRAME_LEN;
    poolOptions.maxBuffersPerPacket = 1;
    poolOptions.memorySegmentSize = 0;
    poolOptions.poolFlags = PoolFlagMapToDext;
    poolOptions.dmaSpecification.maxAddressBits = 64;
    ret = IOUserNetworkPacketBufferPool::CreateWithOptions(
        this, "AQC111", &poolOptions, &ivars->pool);
    if (ret != kIOReturnSuccess) {
        LogE("Start: CreatePacketBufferPool failed: 0x%x", ret);
        goto fail;
    }

    ret = IOUserNetworkTxSubmissionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->txsQueue);
    if (ret != kIOReturnSuccess) { LogE("Start: TxSubmission failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkTxCompletionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->txcQueue);
    if (ret != kIOReturnSuccess) { LogE("Start: TxCompletion failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkRxSubmissionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->rxsQueue);
    if (ret != kIOReturnSuccess) { LogE("Start: RxSubmission failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkRxCompletionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->rxcQueue);
    if (ret != kIOReturnSuccess) { LogE("Start: RxCompletion failed: 0x%x", ret); goto fail; }

    queues[0] = ivars->txsQueue;
    queues[1] = ivars->txcQueue;
    queues[2] = ivars->rxsQueue;
    queues[3] = ivars->rxcQueue;

    ret = SetTxPacketHeadroom(8);
    LogI("Start: SetTxPacketHeadroom(8) -> 0x%x", ret);

    // Push media table to the framework before registering the interface.
    // Without this the kernel has no media table → SIOCGIFMEDIA returns nothing →
    // no "status:" line in ifconfig → networkd never auto-enables the interface.
    {
        const uint32_t opts = kIOUserNetworkMediaOptionFullDuplex |
                              kIOUserNetworkMediaOptionFlowControl;
        IOUserNetworkMediaType mediaTable[] = {
            kIOUserNetworkMediaEthernetNone,
            kIOUserNetworkMediaEthernetAuto,
            kIOUserNetworkMediaEthernet100BaseTX | opts,
            kIOUserNetworkMediaEthernet1000BaseT | opts,
            kIOUserNetworkMediaEthernet2500BaseT | opts,
            kIOUserNetworkMediaEthernet5000BaseT | opts,
        };
        uint32_t mediaCount = sizeof(mediaTable) / sizeof(mediaTable[0]);
        ret = ReportAvailableMediaTypes(mediaTable, mediaCount);
        LogI("Start: ReportAvailableMediaTypes(%u) -> 0x%x", mediaCount, ret);
        if (ret != kIOReturnSuccess) goto fail;
    }

    // Select None before registering — mirrors "no media selected yet" state at start.
    ret = SelectMediaType(kIOUserNetworkMediaEthernetNone, nullptr);
    LogI("Start: SelectMediaType(None=0x%x) -> 0x%x", kIOUserNetworkMediaEthernetNone, ret);
    if (ret != kIOReturnSuccess) goto fail;

    ret = RegisterEthernetInterface(macAddress, ivars->pool, queues, 4);
    if (ret != kIOReturnSuccess) {
        LogE("Start: RegisterEthernetInterface failed: 0x%x", ret);
        goto fail;
    }
    LogI("Start: RegisterEthernetInterface OK");

    // --- TX path ---
    // Wire up TxPacketAvailable: stack notifies via IODataQueueDispatchSource
    // when it enqueues a packet onto txsQueue.
    ret = CreateActionTxPacketAvailable(0, &ivars->txPacketAction);
    if (ret != kIOReturnSuccess) { LogE("Start: CreateActionTxPacketAvailable failed: 0x%x", ret); goto fail; }

    {
        IODataQueueDispatchSource *txDataQueue = nullptr;
        ret = ivars->txsQueue->CopyDataQueue(&txDataQueue);
        LogI("Start: txsQueue CopyDataQueue -> 0x%x dq=%p", ret, txDataQueue);
        if (ret == kIOReturnSuccess && txDataQueue != nullptr) {
            ret = txDataQueue->SetDataAvailableHandler(ivars->txPacketAction);
            LogI("Start: SetDataAvailableHandler -> 0x%x", ret);
            OSSafeReleaseNULL(txDataQueue);
        }
        if (ret != kIOReturnSuccess) goto fail;
    }

    ret = CreateActionOnTxComplete(0, &ivars->txCompleteAction);
    if (ret != kIOReturnSuccess) { LogE("Start: CreateActionOnTxComplete failed: 0x%x", ret); goto fail; }

    // Staging buffer: 8-byte descriptor + max supported Ethernet frame.
    // Interface-created buffers enforce direction-derived CPU mappings; pure
    // Out is read-only to the dext, so the CPU-written TX buffer needs OutIn.
    ret = ivars->interface->CreateIOBuffer(kIOMemoryDirectionOutIn,
        AQC111_TX_BUF_SIZE, &ivars->txBuf);
    if (ret != kIOReturnSuccess) { LogE("Start: txBuf alloc failed: 0x%x", ret); goto fail; }

    // Allocate RX buffers and completion actions. USB I/O is NOT posted here —
    // arming happens in SetInterfaceEnable(true), AFTER hwEnable powers the PHY.
    // This mirrors the x86 driver (AqPacificDriver::enable: hwStart → Rx::start
    // → Itr::start) and Linux (aqc111_reset → usbnet_status_start). Posting the
    // ITR URB before the PHY is alive causes the first completion to capture
    // an autoneg-in-progress state, and the device may not re-signal once
    // autoneg settles — see notes/itr_ordering_analysis.md.
    for (int i = 0; i < RX_SLOTS; i++) {
        ret = ivars->interface->CreateIOBuffer(kIOMemoryDirectionIn, RX_BUF_SIZE, &ivars->rxBufs[i]);
        if (ret != kIOReturnSuccess) {
            LogE("Start: rxBuf[%d] alloc failed: 0x%x", i, ret);
            goto fail;
        }
        ret = CreateActionOnRxComplete(sizeof(uint32_t), &ivars->rxActions[i]);
        if (ret != kIOReturnSuccess) {
            LogE("Start: rxAction[%d] create failed: 0x%x", i, ret);
            goto fail;
        }
        *(uint32_t *)ivars->rxActions[i]->GetReference() = (uint32_t)i;
    }
    LogI("Start: %d RX buffers allocated", RX_SLOTS);

    ret = ivars->interface->CreateIOBuffer(kIOMemoryDirectionIn, 16, &ivars->itrBuf);
    if (ret != kIOReturnSuccess) {
        LogE("Start: itrBuf alloc failed: 0x%x", ret);
        goto fail;
    }
    ret = CreateActionOnItrComplete(0, &ivars->itrAction);
    if (ret != kIOReturnSuccess) {
        LogE("Start: itrAction create failed: 0x%x", ret);
        goto fail;
    }
    LogI("Start: ITR buffer allocated");

    ret = RegisterService();
    LogI("Start: RegisterService -> 0x%x", ret);

    return ret;

fail:
    Stop(provider, SUPERDISPATCH);
    return kIOReturnError;
}

kern_return_t
IMPL(AQC111NIC, Stop)
{
    LogI("Stop: enter");
    ivars->interfaceEnabled = false;
    ivars->ioArmed = false;

    // DispatchSync removed: during force-close/uninstall asyncQueue may not
    // be serviceable, causing DispatchSync to block indefinitely and
    // preventing SUPERDISPATCH from ever being called. Instead: abort pipes
    // directly, then close interface.

    // Abort pipes synchronously before closing the interface.
    // kIOUSBAbortSynchronous ensures completions have fired before returning.
    if (ivars->pipeItr != nullptr) {
        kern_return_t r = ivars->pipeItr->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        LogI("Stop: Abort ITR -> 0x%x", r);
    }
    if (ivars->pipeRx != nullptr) {
        kern_return_t r = ivars->pipeRx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        LogI("Stop: Abort RX -> 0x%x", r);
    }
    if (ivars->pipeTx != nullptr) {
        kern_return_t r = ivars->pipeTx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        LogI("Stop: Abort TX -> 0x%x", r);
    }

    if (ivars->interface != nullptr) {
        kern_return_t r = ivars->interface->Close(this, 0);
        LogI("Stop: Close interface -> 0x%x", r);
    }

    LogI("Stop: releasing objects");
    OSSafeReleaseNULL(ivars->itrAction);
    OSSafeReleaseNULL(ivars->itrBuf);
    for (int i = 0; i < RX_SLOTS; i++) {
        OSSafeReleaseNULL(ivars->rxActions[i]);
        OSSafeReleaseNULL(ivars->rxBufs[i]);
    }
    OSSafeReleaseNULL(ivars->txCompleteAction);
    OSSafeReleaseNULL(ivars->txPacketAction);
    OSSafeReleaseNULL(ivars->txBuf);
    OSSafeReleaseNULL(ivars->rxcQueue);
    OSSafeReleaseNULL(ivars->rxsQueue);
    OSSafeReleaseNULL(ivars->txcQueue);
    OSSafeReleaseNULL(ivars->txsQueue);
    OSSafeReleaseNULL(ivars->pool);
    OSSafeReleaseNULL(ivars->pipeItr);
    OSSafeReleaseNULL(ivars->pipeRx);
    OSSafeReleaseNULL(ivars->pipeTx);
    OSSafeReleaseNULL(ivars->interface);
    OSSafeReleaseNULL(ivars->device);
    OSSafeReleaseNULL(ivars->asyncQueue);
    OSSafeReleaseNULL(ivars->queue);

    LogI("Stop: before SUPERDISPATCH");
    kern_return_t ret = Stop(provider, SUPERDISPATCH);
    LogI("Stop: after SUPERDISPATCH ret=0x%x", ret);
    return ret;
}

kern_return_t
IMPL(AQC111NIC, NewUserClient)
{
    IOService *service = nullptr;

    if (type != 0) {
        LogE("NewUserClient: unsupported type=%u", type);
        return kIOReturnUnsupported;
    }

    kern_return_t ret = Create(this, "AQC111LogUserClientProperties", &service);
    if (ret != kIOReturnSuccess || service == nullptr) {
        LogE("NewUserClient: Create(AQC111LogUserClientProperties) -> 0x%x service=%p", ret, service);
        return ret;
    }

    *userClient = OSDynamicCast(IOUserClient, service);
    if (*userClient == nullptr) {
        LogE("NewUserClient: created service is not IOUserClient");
        OSSafeReleaseNULL(service);
        return kIOReturnUnsupported;
    }

    LogI("NewUserClient: created log user client=%p", *userClient);
    return kIOReturnSuccess;
}

// --- Hardware register access ---
//
// AQ_ACCESS_MAC (bRequest=0x01): read/write device MAC-side SFR registers.
//   OUT (0x40): write len bytes to register at addr; wIndex=wLength=len.
//   IN  (0xC0): read  len bytes from register at addr; wIndex=wLength=len.

static kern_return_t
aqWrite(IOUSBHostInterface *iface, uint16_t addr, const void *data, uint16_t len)
{
    IOBufferMemoryDescriptor *buf = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionOut, len, 0, &buf);
    if (ret != kIOReturnSuccess) return ret;

    IOAddressSegment range;
    buf->GetAddressRange(&range);
    memcpy((void *)range.address, data, len);
    buf->SetLength(len);

    uint16_t transferred = 0;
    ret = iface->DeviceRequest(0x40, 0x01, addr, len, len, buf, &transferred, 10000);
    OSSafeReleaseNULL(buf);
    return ret;
}

static kern_return_t
aqVendorOut(IOUSBHostInterface *iface, uint8_t request, const void *data, uint16_t len)
{
    IOBufferMemoryDescriptor *buf = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionOut, len, 0, &buf);
    if (ret != kIOReturnSuccess) return ret;

    IOAddressSegment range;
    buf->GetAddressRange(&range);
    memcpy((void *)range.address, data, len);
    buf->SetLength(len);

    uint16_t transferred = 0;
    ret = iface->DeviceRequest(0x40, request, 0, 0, len, buf, &transferred, 10000);
    OSSafeReleaseNULL(buf);
    return ret;
}

static kern_return_t
aqRead(IOUSBHostInterface *iface, uint16_t addr, void *data, uint16_t len)
{
    IOBufferMemoryDescriptor *buf = nullptr;
    kern_return_t ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionIn, len, 0, &buf);
    if (ret != kIOReturnSuccess) return ret;
    buf->SetLength(len);

    uint16_t transferred = 0;
    ret = iface->DeviceRequest(0xC0, 0x01, addr, len, len, buf, &transferred, 10000);
    if (ret == kIOReturnSuccess) {
        IOAddressSegment range;
        buf->GetAddressRange(&range);
        memcpy(data, (const void *)range.address, len);
    }
    OSSafeReleaseNULL(buf);
    return ret;
}

static kern_return_t
aqWrite16(IOUSBHostInterface *iface, uint16_t addr, uint16_t value)
{
    uint8_t data[2];
    writeLe16(data, value);
    return aqWrite(iface, addr, data, sizeof(data));
}

static kern_return_t
aqRead16(IOUSBHostInterface *iface, uint16_t addr, uint16_t *value)
{
    uint8_t data[2];
    kern_return_t ret = aqRead(iface, addr, data, sizeof(data));
    if (ret == kIOReturnSuccess && value != nullptr) {
        *value = readLe16(data);
    }
    return ret;
}

static kern_return_t
aqVendorOut32(IOUSBHostInterface *iface, uint8_t request, uint32_t value)
{
    uint8_t data[4];
    writeLe32(data, value);
    return aqVendorOut(iface, request, data, sizeof(data));
}

static kern_return_t
armAsyncIO(AQC111NIC_IVars *ivars)
{
    kern_return_t ret;

    if (ivars->ioArmed) {
        return kIOReturnSuccess;
    }

    for (int i = 0; i < RX_SLOTS; i++) {
        ret = ivars->pipeRx->AsyncIO(ivars->rxBufs[i], RX_BUF_SIZE, ivars->rxActions[i], 0);
        LogD("armAsyncIO: RX[%d] -> 0x%x", i, ret);
        if (ret != kIOReturnSuccess) {
            return ret;
        }
    }

    ret = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
    LogD("armAsyncIO: ITR -> 0x%x", ret);
    if (ret != kIOReturnSuccess) {
        return ret;
    }

    ivars->ioArmed = true;
    return kIOReturnSuccess;
}

static void
disarmAsyncIO(AQC111NIC_IVars *ivars)
{
    kern_return_t r;

    ivars->ioArmed = false;

    if (ivars->pipeItr != nullptr) {
        r = ivars->pipeItr->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        LogD("disarmAsyncIO: Abort ITR -> 0x%x", r);
    }
    if (ivars->pipeRx != nullptr) {
        r = ivars->pipeRx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        LogD("disarmAsyncIO: Abort RX -> 0x%x", r);
    }
}

// Writes the AQ_PHY_OPS advertise word: advertiseMask is AQ_ADV_MASK bits
// (100M=0x1, 1G=0x2, 2.5G=0x4, 5G=0x8) — full autoneg (0xF) normally, or a
// single bit when handleChosenMedia() has forced a specific rate. Shared by
// hwEnable (bring-up) and handleChosenMedia (live runtime change) so the two
// paths can't drift. Matches Linux aqc111_set_phy_speed()'s pause/downshift
// defaults; Retries=3 per Linux default.
static kern_return_t
applyPhyAdvertise(IOUSBHostInterface *iface, uint32_t advertiseMask)
{
    uint32_t phyFlags = 0;
    phyFlags |= (advertiseMask & 0x0000000Fu);  // AQ_ADV_MASK
    phyFlags |= 1u << 16;     // AQ_PAUSE
    phyFlags |= 1u << 17;     // AQ_ASYM_PAUSE
    phyFlags |= 1u << 19;     // AQ_PHY_POWER_EN
    phyFlags |= 1u << 21;     // AQ_DOWNSHIFT
    phyFlags |= 3u << 24;     // AQ_DSH_RETRIES=3
    kern_return_t ret = aqVendorOut32(iface, 0x61, phyFlags);
    LogI("applyPhyAdvertise: AQ_PHY_OPS flags=0x%08x -> 0x%x", phyFlags, ret);
    return ret;
}

// Minimal PHY-only bring-up sequence derived from Linux aqc111.c and the x86
// IOKit RE notes. This intentionally does not enable RX or program the final
// medium state; that belongs on the link-up path once the PHY is alive.
static void
hwEnable(IOUSBHostInterface *iface, const IOUserNetworkMACAddress &mac, uint32_t advertiseMask)
{
    kern_return_t ret;
    uint8_t  b;
    uint16_t w;
    uint32_t phyFlags;

    // Two-step AQ_PHY_OPS sequence mirrors x86 phyAccess->lowPower(false) then
    // phyAccess->advertise(), and Linux aqc111_reset() + aqc111_set_phy_speed().
    // Step 1: exit low-power (POWER_EN only, no advertise bits) so the firmware
    // sees a clean "powered up, not yet advertising" state before we add speed
    // advertisement in step 2. A single combined write may not restart autoneg
    // if the firmware doesn't observe an intermediate state change.
    // NOTE: bRequest=0x31 (AQ_PHY_POWER) is DirectPhyAccess only (major < 0x80)
    // and must NOT be used here. This driver requires FWPhyAccess (major >= 0x80).
    phyFlags = 1u << 19;  // AQ_PHY_POWER_EN only
    ret = aqVendorOut32(iface, 0x61, phyFlags);
    LogI("hwEnable: AQ_PHY_OPS step1 POWER_EN=0x%08x -> 0x%x", phyFlags, ret);

    ret = aqWrite(iface, 0x0010, mac.octet, 6);
    LogI("hwEnable: SFR_NODE_ID -> 0x%x", ret);

    b = 0xFF;
    ret = aqWrite(iface, 0x0041, &b, 1);
    LogI("hwEnable: BM_INT_MASK=0xFF -> 0x%x", ret);

    // Mirror the x86 driver's pre-advertise state clears before asking the PHY
    // to negotiate. These clear MAC/path bits that should not remain latched
    // across bring-up attempts.
    b = 0x00;
    ret = aqWrite(iface, 0x00B1, &b, 1);
    LogI("hwEnable: reg[0x00B1]=0x00 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x0024, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= 0xE0;
        ret = aqWrite(iface, 0x0024, &b, 1);
    }
    LogI("hwEnable: reg[0x0024]&=0xE0 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x000B, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= (uint8_t)~0x80;
        ret = aqWrite(iface, 0x000B, &b, 1);
    }
    LogI("hwEnable: reg[0x000B] clear bit7 -> 0x%x", ret);

    w = 0;
    ret = aqRead16(iface, 0x0022, &w);
    if (ret == kIOReturnSuccess) {
        w &= (uint16_t)~0x0100;
        ret = aqWrite16(iface, 0x0022, w);
    }
    LogI("hwEnable: reg[0x0022] clear bit8 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x00B0, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= (uint8_t)~0x01;
        ret = aqWrite(iface, 0x00B0, &b, 1);
    }
    LogI("hwEnable: reg[0x00B0] clear bit0 -> 0x%x", ret);

    // Step 2: advertisement.
    ret = applyPhyAdvertise(iface, advertiseMask);

    // NOTE: ETH_MAC_PATH, BULK_OUT_CTRL, and coalescing are intentionally
    // NOT programmed here. x86 hwStart and Linux aqc111_reset both stop at
    // advertise(). MAC-path / bulk-out / coalescing are programmed on the
    // link-up edge via hwOnLinkUp() once autoneg actually settles.
}

static kern_return_t
applyMtuToHardware(AQC111NIC_IVars *ivars)
{
    if (ivars == nullptr || ivars->interface == nullptr) {
        return kIOReturnNotReady;
    }

    IOUSBHostInterface *iface = ivars->interface;
    kern_return_t firstError = kIOReturnSuccess;
    kern_return_t r;
    uint16_t medium = 0;
    uint8_t pauseWatermark[AQ_PAUSE_WATERMARK_LEN];
    uint8_t coalesce[AQ_RX_BULK_COALESCE_LEN] = {
        AQ_RX_BULK_QUEUE_CTRL_ALL,
        0x00,
        0x01,
        0x1E,
        0xFF,
    };
    uint32_t mtu = ivars->currentMtu;

    r = aqRead16(iface, AQ_REG_MEDIUM_MODE, &medium);
    if (r == kIOReturnSuccess) {
        if (mtu > AQC111_MIN_MTU) {
            medium |= AQ_MEDIUM_JUMBO_FRAME_ENABLE;
        } else {
            medium &= (uint16_t)~AQ_MEDIUM_JUMBO_FRAME_ENABLE;
        }
        r = aqWrite16(iface, AQ_REG_MEDIUM_MODE, medium);
    }
    if (r != kIOReturnSuccess && firstError == kIOReturnSuccess) {
        firstError = r;
    }
    LogI("applyMtuToHardware: mtu=%u MEDIUM_STATUS_MODE jumbo=%d val=0x%04x -> 0x%x",
        mtu, mtu > AQC111_MIN_MTU, medium, r);

    if (ivars->lastSpeedCode == 0x13) {
        coalesce[AQ_RX_BULK_COALESCE_TIMER_LOW] = 0xA0;
        coalesce[AQ_RX_BULK_COALESCE_TIMER_HIGH] = 0x00;
        coalesce[AQ_RX_BULK_COALESCE_SIZE] = 0x14;
        coalesce[AQ_RX_BULK_COALESCE_IFG] = 0x00;
    }
    if (mtu > 12500) {
        coalesce[AQ_RX_BULK_COALESCE_CTRL] = AQ_RX_BULK_QUEUE_CTRL_ALL;
        coalesce[AQ_RX_BULK_COALESCE_TIMER_LOW] = 0x00;
        coalesce[AQ_RX_BULK_COALESCE_TIMER_HIGH] = 0x01;
        coalesce[AQ_RX_BULK_COALESCE_SIZE] = 0x18;
        coalesce[AQ_RX_BULK_COALESCE_IFG] = 0xFF;
    }

    r = aqWrite(iface, AQ_REG_RX_BULK_QUEUE_CTRL, coalesce, sizeof(coalesce));
    if (r != kIOReturnSuccess && firstError == kIOReturnSuccess) {
        firstError = r;
    }
    LogI("applyMtuToHardware: mtu=%u coalesce=%02x %02x %02x %02x %02x -> 0x%x",
        mtu,
        coalesce[AQ_RX_BULK_COALESCE_CTRL],
        coalesce[AQ_RX_BULK_COALESCE_TIMER_LOW],
        coalesce[AQ_RX_BULK_COALESCE_TIMER_HIGH],
        coalesce[AQ_RX_BULK_COALESCE_SIZE],
        coalesce[AQ_RX_BULK_COALESCE_IFG],
        r);

    if (mtu <= 4500) {
        pauseWatermark[AQ_PAUSE_WATERMARK_LOW_BYTE] = 0x10;
        pauseWatermark[AQ_PAUSE_WATERMARK_HIGH_BYTE] = 0x08;
    } else if (mtu <= 9500) {
        pauseWatermark[AQ_PAUSE_WATERMARK_LOW_BYTE] = 0x20;
        pauseWatermark[AQ_PAUSE_WATERMARK_HIGH_BYTE] = 0x10;
    } else if (mtu <= 12500) {
        pauseWatermark[AQ_PAUSE_WATERMARK_LOW_BYTE] = 0x20;
        pauseWatermark[AQ_PAUSE_WATERMARK_HIGH_BYTE] = 0x14;
    } else {
        pauseWatermark[AQ_PAUSE_WATERMARK_LOW_BYTE] = 0x20;
        pauseWatermark[AQ_PAUSE_WATERMARK_HIGH_BYTE] = 0x1A;
    }

    r = aqWrite(iface, AQ_REG_PAUSE_WATERMARK, pauseWatermark, sizeof(pauseWatermark));
    if (r != kIOReturnSuccess && firstError == kIOReturnSuccess) {
        firstError = r;
    }
    LogI("applyMtuToHardware: mtu=%u pause_watermark=%02x %02x -> 0x%x",
        mtu,
        pauseWatermark[AQ_PAUSE_WATERMARK_LOW_BYTE],
        pauseWatermark[AQ_PAUSE_WATERMARK_HIGH_BYTE],
        r);

    return firstError;
}

static void
hwOnLinkUp(AQC111NIC_IVars *ivars, uint8_t speedCode)
{
    kern_return_t r;
    IOUSBHostInterface *iface = ivars->interface;
    uint16_t rxCtl;
    uint16_t medium;
    uint8_t b;
    uint32_t speedMbps = linkSpeedMbps(speedCode);

    LogI("hwOnLinkUp: link speed %u Mbps (code=0x%02x)", speedMbps, speedCode);

    // Mirror the Linux/x86 receive-start sequence on actual link-up.
    rxCtl = 0x0000;
    r = aqWrite16(iface, 0x000B, rxCtl);
    LogI("hwOnLinkUp: RX_CTL=0x0000 -> 0x%x", r);

    // Linux aqc111_link_reset zeroes the buffer-manager DMA controls and ARC
    // control on every link-up rather than trusting firmware defaults; mirror
    // it. (Probed 2026-07-03: firmware defaults were already zero, so this is
    // parity insurance, not a behavior change — see TESTING.md TSO section.)
    b = 0x00;
    r = aqWrite(iface, 0x0043, &b, 1);   // SFR_BMRX_DMA_CONTROL
    LogI("hwOnLinkUp: BMRX_DMA_CONTROL=0x00 -> 0x%x", r);
    b = 0x00;
    r = aqWrite(iface, 0x0046, &b, 1);   // SFR_BMTX_DMA_CONTROL
    LogI("hwOnLinkUp: BMTX_DMA_CONTROL=0x00 -> 0x%x", r);
    b = 0x00;
    r = aqWrite(iface, 0x009E, &b, 1);   // SFR_ARC_CTRL
    LogI("hwOnLinkUp: ARC_CTRL=0x00 -> 0x%x", r);

    b = 0x01;
    r = aqWrite(iface, 0x00B7, &b, 1);
    LogI("hwOnLinkUp: ETH_MAC_PATH=0x01 -> 0x%x", r);

    b = 0x02;
    r = aqWrite(iface, 0x00B9, &b, 1);
    LogI("hwOnLinkUp: BULK_OUT_CTRL=0x02 -> 0x%x", r);

    // Hardware won't populate the RX descriptor's checksum status bits at all
    // unless this is set. Written unconditionally; forwarding the result to
    // the stack is gated separately in OnRxComplete on the OS-controlled
    // hwAssistMask (see IMPL_PLAN.md M6a).
    b = SFR_RXCOE_IP | SFR_RXCOE_TCP | SFR_RXCOE_UDP | SFR_RXCOE_TCPV6 | SFR_RXCOE_UDPV6;
    r = aqWrite(iface, SFR_RXCOE_CTL, &b, 1);
    LogI("hwOnLinkUp: RXCOE_CTL=0x%02x -> 0x%x", b, r);

    // TX checksum offload: pure link-level toggle, no per-packet descriptor
    // bit (see IMPL_PLAN.md TX checksum offload). Once enabled, hardware
    // auto-detects and fixes up every outgoing IP/TCP/UDP frame's checksum.
    b = SFR_TXCOE_IP | SFR_TXCOE_TCP | SFR_TXCOE_UDP | SFR_TXCOE_TCPV6 | SFR_TXCOE_UDPV6;
    r = aqWrite(iface, SFR_TXCOE_CTL, &b, 1);
    LogI("hwOnLinkUp: TXCOE_CTL=0x%02x -> 0x%x", b, r);

    ivars->lastSpeedCode = speedCode;
    r = applyMtuToHardware(ivars);
    LogI("hwOnLinkUp: applyMtuToHardware(mtu=%u speed=%u Mbps code=0x%02x) -> 0x%x",
        ivars->currentMtu, speedMbps, speedCode, r);

    medium = AQ_MEDIUM_FULL_DUPLEX | AQ_MEDIUM_RX_FLOW_CONTROL | AQ_MEDIUM_TX_FLOW_CONTROL;
    if (speedCode == 0x0F || speedCode == 0x10) {
        medium |= AQ_MEDIUM_XGMII_MODE;  // XGMII mode for 5G / 2.5G
    }
    if (ivars->currentMtu > AQC111_MIN_MTU) {
        medium |= AQ_MEDIUM_JUMBO_FRAME_ENABLE;
    }
    r = aqWrite16(iface, AQ_REG_MEDIUM_MODE, medium);
    LogI("hwOnLinkUp: MEDIUM_STATUS_MODE=0x%04x -> 0x%x", medium, r);

    medium |= AQ_MEDIUM_RECEIVE_ENABLE;
    r = aqWrite16(iface, AQ_REG_MEDIUM_MODE, medium);
    LogI("hwOnLinkUp: MEDIUM_STATUS_MODE|=RECEIVE_EN => 0x%04x -> 0x%x", medium, r);

    // Keep 802.1Q tags inline for the OS vlan(4) software path. Enabling
    // hardware strip here removes the tag before Skywalk can demux to vlan0
    // unless we also forward RX descriptor VLAN metadata, which this layer-1
    // VLAN support pass intentionally does not do.
    b = AQ_VLAN_CONTROL_NONE;
    r = aqWrite(iface, AQ_REG_VLAN_CONTROL, &b, 1);
    LogI("hwOnLinkUp: VLAN_CONTROL=0x%02x (strip off) -> 0x%x", b, r);

    // The x86 path also touches speed-dependent secondary controls here
    // (0x0046, 0x009e). Keep this patch minimal and focus first on the
    // must-have RX producer enables.
    rxCtl = 0x0288 | ivars->rxFilterBits;  // base: IPE | START | AB, plus any OS-requested filter bits
    r = aqWrite16(iface, 0x000B, rxCtl);
    LogI("hwOnLinkUp: RX_CTL=0x%04x -> 0x%x", rxCtl, r);
    LogI("pmCounters at linkup: off=%u on=%u low=%u other=%u",
        ivars->pmOffCount, ivars->pmOnCount, ivars->pmLowCount, ivars->pmOtherCount);
}

static void
hwOnLinkDown(IOUSBHostInterface *iface)
{
    kern_return_t r;
    uint16_t rxCtl;
    uint16_t medium;

    rxCtl = 0x0000;
    r = aqWrite16(iface, 0x000B, rxCtl);
    LogI("hwOnLinkDown: RX_CTL=0x0000 -> 0x%x", r);

    medium = 0;
    r = aqRead16(iface, 0x0022, &medium);
    LogI("hwOnLinkDown: read MEDIUM_STATUS_MODE -> 0x%x val=0x%04x", r, medium);
    if (r == kIOReturnSuccess) {
        medium &= (uint16_t)~0x0100;
        r = aqWrite16(iface, 0x0022, medium);
    }
    LogI("hwOnLinkDown: MEDIUM_STATUS_MODE&=~RECEIVE_EN => 0x%04x -> 0x%x", medium, r);
}

static void
ensureRxStarted(AQC111NIC_IVars *ivars, uint8_t speedCode)
{
    if (ivars == nullptr || !ivars->interfaceEnabled) {
        return;
    }
    if (ivars->rxStarted) {
        LogI("ensureRxStarted: already started");
        return;
    }
    hwOnLinkUp(ivars, speedCode);
    ivars->rxStarted = true;
    LogI("ensureRxStarted: started link speed %u Mbps (code=0x%02x)", linkSpeedMbps(speedCode), speedCode);
}

static void
ensureRxStopped(AQC111NIC_IVars *ivars)
{
    if (ivars == nullptr) {
        return;
    }
    if (!ivars->rxStarted) {
        LogI("ensureRxStopped: already stopped");
        return;
    }
    hwOnLinkDown(ivars->interface);
    ivars->rxStarted = false;
    LogI("ensureRxStopped: stopped");
}

// Parse the RX aggregation header: an 8-byte header in the final 8 bytes of
// the USB transfer, packet data starting at offset 0. Confirmed three ways:
// the Linux driver's source (notes/aqc111.c aqc111_rx_fixup, notes/aqc111.h
// AQ_RX_DH_PKT_CNT_MASK/AQ_RX_DH_DESC_OFFSET_MASK), corrected x86 kext
// disassembly (RE_LOG.md "RX Bulk IN Buffer Layout"), and live-traffic
// logging of every candidate layout previously considered (see
// IMPL_PLAN.md "Bug fix plan — RX aggregation header layout guessing").
static bool
parseRxLayout(const uint8_t *buf, uint32_t actualByteCount, RxParseInfo *info)
{
    if (buf == nullptr || info == nullptr || actualByteCount < 8) {
        return false;
    }

    uint32_t headerOffset = actualByteCount - 8;
    uint32_t header    = readLe32(buf + headerOffset);
    uint32_t pktCount  = header & 0x1FFF;
    uint32_t descOff   = (header & 0xFFFFE000) >> 13;
    uint32_t descBytes = pktCount * 8;

    if (pktCount == 0 || descOff + descBytes > headerOffset) {
        return false;
    }

    // Packets are padded to an 8-byte boundary (notes/aqc111.c
    // pkt_len_with_padd = (pkt_len + 7) & 0x7FFF8) — walk with that padding
    // applied or multi-packet buffers misparse from the second packet on.
    uint32_t pktOffset = 0;
    for (uint32_t i = 0; i < pktCount; i++) {
        uint64_t pd      = readLe64(buf + descOff + i * 8);
        uint32_t pktLen  = (uint32_t)((pd & 0x7FFF0000) >> 16);

        if (pktLen == 0) {
            return false;
        }
        uint32_t pktLenPadded = (pktLen + 7u) & ~7u;
        if (pktOffset + pktLenPadded > descOff) {
            return false;
        }
        pktOffset += pktLenPadded;
    }

    info->descriptorOffset = descOff;
    info->packetCount      = pktCount;
    return true;
}

static void
hwDisable(IOUSBHostInterface *iface)
{
    kern_return_t r;
    uint32_t phyFlags;
    uint16_t w;
    uint8_t  b;

    // TODO: SFR_RXCOE_CTL/SFR_TXCOE_CTL are never cleared here (or anywhere
    // in this file). They're sticky across dext Stop/Start cycles since the
    // chip itself doesn't lose power — confirmed empirically during TX
    // checksum offload negative-control testing (see TESTING.md). Linux's
    // aqc111_stop()/link_reset(down) also never clears them, so this isn't
    // unique to us, but it's still "leave hardware in an undefined state on
    // teardown" — investigate whether hwDisable() should explicitly write
    // 0x00 to both registers, matching the rest of this function's pattern
    // of actively undoing what hwEnable/hwOnLinkUp set up, rather than
    // relying on the next hwOnLinkUp to overwrite it correctly anyway.
    w = 0x0000;
    r = aqWrite16(iface, 0x000B, w);
    LogI("hwDisable: RX_CTL=0x0000 -> 0x%x", r);

    w = 0;
    r = aqRead16(iface, 0x0022, &w);
    LogI("hwDisable: read MEDIUM_STATUS_MODE -> 0x%x val=0x%04x", r, w);
    w &= ~(uint16_t)0x0100;
    r = aqWrite16(iface, 0x0022, w);
    LogI("hwDisable: MEDIUM_STATUS_MODE=0x%04x (clear RECEIVE_EN) -> 0x%x", w, r);

    b = 0x00;
    r = aqWrite(iface, 0x00B7, &b, 1);
    LogI("hwDisable: ETH_MAC_PATH=0x00 -> 0x%x", r);

    b = 0x00;
    r = aqWrite(iface, 0x00B9, &b, 1);
    LogI("hwDisable: BULK_OUT_CTRL=0x00 -> 0x%x", r);

    b = 0x00;
    r = aqWrite(iface, 0x0043, &b, 1);
    LogI("hwDisable: BMRX_DMA=0x00 -> 0x%x", r);

    phyFlags = 0;
    r = aqVendorOut32(iface, 0x61, phyFlags);
    LogI("hwDisable: AQ_PHY_OPS withdraw advertise flags=0x%08x -> 0x%x", phyFlags, r);

    phyFlags = (1u << 18) | (1u << 19);
    r = aqVendorOut32(iface, 0x61, phyFlags);
    LogI("hwDisable: AQ_PHY_OPS lowPower flags=0x%08x -> 0x%x", phyFlags, r);
}

// --- TX path ---
//
// Wire format (SFR_BULK_OUT_EFF_EN=0x02 already set in hwEnable):
//   [uint64_t descriptor LE: bits 20:0=frame_len, all others 0][raw Ethernet frame]
// Matches Linux aqc111_tx_fixup and x86 kext. One frame in flight at a time.

static void
txDrainOne(AQC111NIC_IVars *ivars)
{
    if (ivars->txBusy || !ivars->interfaceEnabled || !ivars->ioArmed) {
        return;
    }

    IOUserNetworkPacket *packets[1];
    uint32_t count = ivars->txsQueue->DequeuePackets(packets, 1);
    if (count == 0) return;

    IOUserNetworkPacket *pkt = packets[0];
    uint16_t dataOffset = pkt->getDataOffset();
    uint32_t dataLen    = pkt->getDataLength();
    const uint8_t *frame = (const uint8_t *)(uintptr_t)pkt->getDataVirtualAddress() + dataOffset;

    LogD("txDrainOne: pkt=%p offset=%u len=%u", pkt, (unsigned)dataOffset, dataLen);

    // Diagnostic for IMPL_PLAN.md M6e VLAN investigation — does the OS deliver
    // the 802.1Q tag inline in the buffer bytes (frame[12:13]==0x8100), as
    // metadata via getVlanTag(), both, or neither? Dump enough bytes to see
    // dst/src MAC + the ethertype/TPID position either way.
    {
        uint16_t vlanTag = 0;
        bool hasVlanTag = pkt->getVlanTag(&vlanTag);
        uint32_t dumpLen = dataLen < 20 ? dataLen : 20;
        char hexbuf[64] = {0};
        int hexoff = 0;
        for (uint32_t i = 0; i < dumpLen && hexoff < (int)sizeof(hexbuf) - 3; i++) {
            hexoff += snprintf(hexbuf + hexoff, sizeof(hexbuf) - (size_t)hexoff, "%02x ", frame[i]);
        }
        LogD("txDrainOne: getVlanTag has=%d tag=%u dataLen=%u first%u: %{public}s",
            hasVlanTag, vlanTag, dataLen, dumpLen, hexbuf);
    }

    // Diagnostic only — the hardware auto-detects IP/TCP/UDP headers and
    // fixes up the checksum itself once SFR_TXCOE_CTL is enabled, so we
    // don't need start/stuff to do the work. Logging what the OS actually
    // requested per-packet, mirroring the RX checksum readback pattern, for
    // verification (see IMPL_PLAN.md TX checksum offload / TESTING.md).
    {
        IOUserNetworkPacketTxChecksumFlags txCsumFlags = 0;
        uint16_t txCsumStart = 0;
        uint16_t txCsumStuff = 0;
        pkt->getTxChecksumInfo(&txCsumFlags, &txCsumStart, &txCsumStuff);
        LogD("txDrainOne: getTxChecksumInfo flags=0x%x start=%u stuff=%u",
            txCsumFlags, txCsumStart, txCsumStuff);
    }

    // TSO (IMPL_PLAN.md M10): segsz > 0 marks a super-packet the device must
    // segment into MSS-sized frames; such packets legitimately exceed the MTU.
    uint16_t tsoSegsz = 0;
    IOUserNetworkPacketTSOFlags tsoFlags = 0;
    pkt->getTSOInfo(&tsoSegsz, &tsoFlags);

    uint32_t maxFrameLen = (tsoSegsz > 0)
        ? AQC111_TSO_MAX_FRAME_LEN
        : ivars->currentMtu + AQC111_ETH_HEADER_LEN + AQC111_VLAN_TAG_LEN;
    if (dataLen == 0 || dataLen > maxFrameLen) {
        LogE("txDrainOne: bad len=%u max=%u mtu=%u, dropping",
            dataLen, maxFrameLen, ivars->currentMtu);
        pkt->setCompletionStatus(kIOReturnError);
        ivars->txcQueue->EnqueuePacket(pkt);
        return;
    }

    // Build USB TX buffer: 8-byte LE descriptor + raw Ethernet frame.
    // Descriptor bits 20:0 = frame length; bits 46:32 = TSO MSS (0 = no TSO).
    // Matches Linux aqc111_tx_fixup and x86 kext with SFR_BULK_OUT_EFF_EN=0x02.
    IOAddressSegment range;
    ivars->txBuf->GetAddressRange(&range);
    uint8_t *txp = (uint8_t *)range.address;
    uint64_t txDesc = (uint64_t)dataLen;  // bits 20:0 = length
    if (tsoSegsz > 0) {
        txDesc |= ((uint64_t)tsoSegsz & AQ_TX_DESC_MSS_MASK) << AQ_TX_DESC_MSS_SHIFT;
        LogD("txDrainOne: TSO segsz=%u flags=0x%x len=%u", tsoSegsz, tsoFlags, dataLen);
    }

    // Pad the transfer to an 8-byte multiple; if that lands exactly on a
    // bulk-OUT maxpacket boundary, add 8 more and flag DROP_PADD so the
    // device discards them. Linux aqc111_tx_fixup does this for every frame.
    uint32_t padding = (8 - ((dataLen + AQC111_TX_DESC_LEN) % 8)) % 8;
    if (((dataLen + AQC111_TX_DESC_LEN + padding) % AQC111_BULK_OUT_MAXPACKET) == 0) {
        padding += 8;
        txDesc |= AQ_TX_DESC_DROP_PADD;
    }

    writeLe64(txp, txDesc);
    memcpy(txp + AQC111_TX_DESC_LEN, frame, dataLen);
    if (padding > 0) {
        memset(txp + AQC111_TX_DESC_LEN + dataLen, 0, padding);
    }
    uint32_t txLen = AQC111_TX_DESC_LEN + dataLen + padding;
    ivars->txBuf->SetLength(txLen);

    LogV("txDrainOne: desc=%016llx frame_len=%u usb_len=%u first16: "
        "%02x %02x %02x %02x %02x %02x %02x %02x  "
        "%02x %02x %02x %02x %02x %02x %02x %02x",
        (unsigned long long)txDesc, dataLen, txLen,
        txp[0],  txp[1],  txp[2],  txp[3],  txp[4],  txp[5],  txp[6],  txp[7],
        txp[8],  txp[9],  txp[10], txp[11], txp[12], txp[13], txp[14], txp[15]);
    // Deeper dump for TX checksum offload verification — covers Ethernet
    // header (14) + IP header (20, +options) + start of TCP/UDP header
    // including the checksum field, so the before/after-offload comparison
    // (software-computed vs. left-zeroed-for-hardware) is actually visible.
    // See IMPL_PLAN.md TX checksum offload / TESTING.md.
    if (txLen >= 64) {
        LogV("txDrainOne: bytes16-63: "
            "%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x  "
            "%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x  "
            "%02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x",
            txp[16], txp[17], txp[18], txp[19], txp[20], txp[21], txp[22], txp[23],
            txp[24], txp[25], txp[26], txp[27], txp[28], txp[29], txp[30], txp[31],
            txp[32], txp[33], txp[34], txp[35], txp[36], txp[37], txp[38], txp[39],
            txp[40], txp[41], txp[42], txp[43], txp[44], txp[45], txp[46], txp[47],
            txp[48], txp[49], txp[50], txp[51], txp[52], txp[53], txp[54], txp[55],
            txp[56], txp[57], txp[58], txp[59], txp[60], txp[61], txp[62], txp[63]);
    }

    ivars->txInFlight = pkt;
    ivars->txBusy     = true;

    kern_return_t r = ivars->pipeTx->AsyncIO(ivars->txBuf, txLen, ivars->txCompleteAction, 0);
    LogD("txDrainOne: AsyncIO -> 0x%x", r);
    if (r != kIOReturnSuccess) {
        ivars->txBusy     = false;
        ivars->txInFlight = nullptr;
        pkt->setCompletionStatus(r);
        ivars->txcQueue->EnqueuePacket(pkt);
    }
}

void
IMPL(AQC111NIC, TxPacketAvailable)
{
    LogD("TxPacketAvailable: fired");
    txDrainOne(ivars);
}

void
IMPL(AQC111NIC, OnTxComplete)
{
    LogD("OnTxComplete: status=0x%x bytes=%u", status, actualByteCount);

    IOUserNetworkPacket *pkt = ivars->txInFlight;
    ivars->txInFlight = nullptr;
    ivars->txBusy     = false;

    if (pkt != nullptr) {
        pkt->setCompletionStatus(status == kIOReturnSuccess ? kIOReturnSuccess : kIOReturnError);
        kern_return_t r = ivars->txcQueue->EnqueuePacket(pkt);
        LogD("OnTxComplete: EnqueuePacket -> 0x%x", r);
    }

    // Drain next queued packet if one arrived while we were in flight
    txDrainOne(ivars);
}

// --- RX path ---

void
IMPL(AQC111NIC, OnRxComplete)
{
    uint32_t slot = *(uint32_t *)action->GetReference();
    LogD("OnRxComplete: slot=%u status=0x%x bytes=%u", slot, status, actualByteCount);

    if (status == kIOReturnAborted) {
        return;  // Stop in progress — don't repost
    }
    if (!ivars->interfaceEnabled || !ivars->ioArmed) {
        LogD("RX[%u] disabled path — not reposting", slot);
        return;
    }
    if (status == kUSBHostReturnPipeStalled) {
        kern_return_t r = ivars->pipeRx->ClearStall(false);
        LogE("RX[%u] stall ClearStall -> 0x%x", slot, r);
        r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        LogE("RX[%u] stall repost -> 0x%x", slot, r);
        return;
    }
    if (status != kIOReturnSuccess) {
        // Terminal (device removed, not ready, etc.) — do NOT repost.
        LogE("RX[%u] terminal error: status=0x%x — not reposting", slot, status);
        return;
    }
    if (actualByteCount < 4) {
        kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        LogD("RX[%u] short buffer repost -> 0x%x", slot, r);
        return;
    }

    // Parse aggregated RX buffer (see parseRxLayout for the confirmed
    // header layout).
    IOAddressSegment range;
    ivars->rxBufs[slot]->GetAddressRange(&range);
    const uint8_t *buf = (const uint8_t *)range.address;
    RxParseInfo layout = {};

    if (!parseRxLayout(buf, actualByteCount, &layout)) {
        kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        LogD("RX[%u] bad header repost -> 0x%x", slot, r);
        return;
    }

    LogD("RX[%u] parsed layout: desc=%u count=%u",
        slot, layout.descriptorOffset, layout.packetCount);

    uint32_t pkt_offset = 0;
    uint32_t delivered  = 0;

    for (uint32_t i = 0; i < layout.packetCount; i++) {
        uint64_t pd      = readLe64(buf + layout.descriptorOffset + i * 8);
        bool     drop    = (pd >> 31) & 1;
        bool     ok      = (pd >> 11) & 1;
        uint32_t pkt_len = (uint32_t)((pd & 0x7FFF0000) >> 16);
        uint32_t pkt_len_padded = (pkt_len + 7u) & ~7u;

        if (!drop && ok && pkt_len > 2) {
            uint32_t frame_len = pkt_len - 2;

            if (frame_len < 14) {
                LogD("RX[%u] frame[%u] too short for Ethernet: pkt_len=%u frame_len=%u",
                    slot, i, pkt_len, frame_len);
                pkt_offset += pkt_len_padded;
                continue;
            }
            if (frame_len > ivars->currentMtu + AQC111_ETH_HEADER_LEN + AQC111_VLAN_TAG_LEN) {
                LogE("RX[%u] frame[%u] too large: pkt_len=%u frame_len=%u max=%u mtu=%u",
                    slot, i, pkt_len, frame_len,
                    ivars->currentMtu + AQC111_ETH_HEADER_LEN + AQC111_VLAN_TAG_LEN, ivars->currentMtu);
                pkt_offset += pkt_len_padded;
                continue;
            }

            const uint8_t *frame = buf + pkt_offset + 2;
            uint16_t etherType = ((uint16_t)frame[12] << 8) | frame[13];
            LogD("RX[%u] frame[%u]: pkt_len=%u frame_len=%u dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x",
                slot, i, pkt_len, frame_len,
                frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
                frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
                etherType);
            if (frame_len >= 32) {
                LogV("RX[%u] frame[%u] first32: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    slot, i,
                    frame[0], frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7],
                    frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
                    frame[16], frame[17], frame[18], frame[19], frame[20], frame[21], frame[22], frame[23],
                    frame[24], frame[25], frame[26], frame[27], frame[28], frame[29], frame[30], frame[31]);
            } else {
                LogV("RX[%u] frame[%u] first32 unavailable: frame_len=%u", slot, i, frame_len);
            }

            IOUserNetworkPacket *pkt = nullptr;
            IOReturn allocRet = ivars->pool->allocatePacket(&pkt);
            if (allocRet == kIOReturnSuccess && pkt != nullptr) {
                uint8_t *dst = (uint8_t *)pkt->getDataVirtualAddress();
                memcpy(dst, frame, frame_len);

                IOReturn prepRet = pkt->prepareWithQueue(ivars->rxcQueue, kIOUserNetworkPacketDirectionRx);
                IOReturn offRet = pkt->setDataOffsetAndLength(0, frame_len);
                IOReturn lhlRet = pkt->setLinkHeaderLength(14);

                if (ivars->hwAssistMask & kIOUserNetworkHWAssistRxChecksum) {
                    uint16_t csumBits = (uint16_t)pd;
                    bool     l4Err  = csumBits & AQ_RX_PD_L4_ERR;
                    bool     l3Err  = csumBits & AQ_RX_PD_L3_ERR;
                    uint8_t  l4Type = (csumBits & AQ_RX_PD_L4_TYPE_MASK) >> AQ_RX_PD_L4_TYPE_SHIFT;
                    uint8_t  l3Type = (csumBits & AQ_RX_PD_L3_TYPE_MASK) >> AQ_RX_PD_L3_TYPE_SHIFT;

                    IOUserNetworkPacketRxChecksumFlags csumFlags = 0;
                    if (l3Type == AQ_RX_PD_L3_IPV4 && !l3Err) {
                        csumFlags |= kIOUserNetworkPacketRxCsumIPChecked | kIOUserNetworkPacketRxCsumIPValid;
                    }
                    // Also gated on !l3Err: a corrupted IP header means the source/dest
                    // addresses feeding the TCP/UDP pseudo-header checksum are unreliable,
                    // so the hardware's L4 check can't be trusted even if it reports clean.
                    // Matches Linux aqc111_rx_checksum's combined L3_ERR||L4_ERR gate; the
                    // x86 kext RE checks these independently, but the safety principle here
                    // (never assert validity on an uncertain packet) favors the stricter read.
                    if ((l4Type == AQ_RX_PD_L4_UDP || l4Type == AQ_RX_PD_L4_TCP) && !l4Err && !l3Err) {
                        csumFlags |= kIOUserNetworkPacketRxCsumDataValid;
                    }
                    IOUserNetworkPacketRxChecksumFlags readback = 0;
                    uint16_t readbackValue = 0;
                    if (csumFlags != 0) {
                        pkt->setRxChecksumInfo(csumFlags, 0);
                        // Readback proves the packet object actually persisted what we set —
                        // a direct round-trip on our own object, immune to the Skywalk
                        // BSD-compat capability synthesis that makes ifconfig untrustworthy
                        // for this. See IMPL_PLAN.md M6a.
                        pkt->getRxChecksumInfo(&readback, &readbackValue);
                    }
                    LogD("RX[%u] frame[%u] checksum: l3Type=%u l3Err=%d l4Type=%u l4Err=%d csumFlags=0x%x readback=0x%x",
                        slot, i, l3Type, l3Err, l4Type, l4Err, csumFlags, readback);
                }

                pkt->setCompletionStatus(kIOReturnSuccess);
                IOUserNetworkPacket *packetArray[1] = { pkt };
                IOReturn enqRet = ivars->rxcQueue->enqueuePackets(packetArray, 1);
                LogD("RX[%u] frame[%u] packet metadata: prepare=0x%x offLen=0x%x linkHdr=0x%x enqueuePackets=0x%x",
                    slot, i, prepRet, offRet, lhlRet, enqRet);

                if (enqRet == kIOReturnSuccess) {
                    delivered++;
                } else {
                    IOReturn deallocRet = ivars->pool->deallocatePacket(pkt);
                    LogE("RX[%u] frame[%u] deallocate after enqueue failure -> 0x%x",
                        slot, i, deallocRet);
                }
            } else {
                LogE("RX[%u] frame[%u] allocatePacket failed -> 0x%x pkt=%p",
                    slot, i, allocRet, pkt);
            }
        }

        pkt_offset += pkt_len_padded;
    }

    if (delivered > 0) {
        LogD("RX[%u] %u bytes → %u/%u frames delivered", slot, actualByteCount, delivered, layout.packetCount);
    }

    kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
    LogD("RX[%u] repost -> 0x%x", slot, r);
}

// --- ITR (interrupt IN) path — link status ---
//
// byte[1]: bit7=link-up, bits[6:0]=speed code
//   0x0F=5G, 0x10=2.5G, 0x11=1G, 0x13=100M

void
IMPL(AQC111NIC, OnItrComplete)
{
    LogD("OnItrComplete: status=0x%x bytes=%u", status, actualByteCount);

    // True teardown: device removed (force close) or our own Abort in Stop().
    if (status == kIOReturnAborted || status == kIOReturnNotAttached) {
        return;
    }
    // Our own teardown path: Stop() clears ioArmed before calling Abort.
    if (!ivars->ioArmed) {
        LogD("ITR: ioArmed=false — not reposting");
        return;
    }
    if (status == kUSBHostReturnPipeStalled) {
        kern_return_t r = ivars->pipeItr->ClearStall(false);
        LogE("ITR stall ClearStall -> 0x%x", r);
        r = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
        LogE("ITR stall repost -> 0x%x", r);
        return;
    }
    // Transient non-success: log but fall through to repost — pipe must stay alive.
    if (status != kIOReturnSuccess) {
        LogD("ITR: transient status=0x%x — reposting", status);
    }

    if (status == kIOReturnSuccess && actualByteCount >= 2) {
        IOAddressSegment range;
        ivars->itrBuf->GetAddressRange(&range);
        const uint8_t *data = (const uint8_t *)range.address;

        uint8_t byte1     = data[1];
        bool    linkUp    = (byte1 >> 7) & 1;
        uint8_t speedCode = byte1 & 0x7F;

        // Always cache link state — mirrors Linux aqc111_status() which caches
        // link/speed from the interrupt regardless of whether the interface is
        // fully open. SetInterfaceEnable(true) reads these to reconcile without
        // waiting for another interrupt edge (fixes no-RX on first ifconfig up).
        ivars->lastLinkUp = linkUp;
        if (linkUp && speedCode != 0)
            ivars->lastSpeedCode = speedCode;

        if (ivars->interfaceEnabled) {
            const uint32_t opts = kIOUserNetworkMediaOptionFullDuplex |
                                  kIOUserNetworkMediaOptionFlowControl;
            MediaWord media = kIOUserNetworkMediaEthernetAuto;
            if (linkUp) {
                ensureRxStarted(ivars, speedCode);
                switch (speedCode) {
                    case 0x0F: media = kIOUserNetworkMediaEthernet5000BaseT | opts; break;
                    case 0x10: media = kIOUserNetworkMediaEthernet2500BaseT | opts; break;
                    case 0x11: media = kIOUserNetworkMediaEthernet1000BaseT | opts; break;
                    case 0x13: media = kIOUserNetworkMediaEthernet100BaseTX | opts; break;
                    default:   media = kIOUserNetworkMediaEthernet1000BaseT | opts; break;
                }
            } else {
                ensureRxStopped(ivars);
            }
            LinkStatus ls = linkUp ? kIOUserNetworkLinkStatusActive
                                   : kIOUserNetworkLinkStatusInactive;
            IOReturn lsRet = reportLinkStatus(ls, media);
            LogI("ITR: link %s speed %u Mbps (code=0x%02x) -> reportLinkStatus(0x%x, 0x%x) -> 0x%x",
                linkUp ? "up" : "down", linkUp ? linkSpeedMbps(speedCode) : 0, speedCode, ls, media, lsRet);
        } else {
            LogD("ITR: byte1=0x%02x linkUp=%d speed=%u Mbps code=0x%02x (cached, interfaceEnabled=false)",
                byte1, (int)linkUp, linkUp ? linkSpeedMbps(speedCode) : 0, speedCode);
        }
    }

    kern_return_t r = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
    LogD("ITR repost -> 0x%x", r);
}

// --- LOCAL overrides ---

kern_return_t
IMPL(AQC111NIC, SetMTU)
{
    return setCurrentMtu(ivars, mtu, "SetMTU");
}

kern_return_t
IMPL(AQC111NIC, GetMaxTransferUnit)
{
    LogI("GetMaxTransferUnit -> %u", AQC111_MAX_MTU);
    *mtu = AQC111_MAX_MTU;
    return kIOReturnSuccess;
}

IOReturn
AQC111NIC::setMaxTransferUnit(uint32_t mtu)
{
    return setCurrentMtu(ivars, mtu, "setMaxTransferUnit");
}

uint32_t
AQC111NIC::getMaxTransferUnit()
{
    LogI("getMaxTransferUnit -> %u", AQC111_MAX_MTU);
    return AQC111_MAX_MTU;
}

kern_return_t
IMPL(AQC111NIC, SetHardwareAssists)
{
    LogI("SetHardwareAssists: 0x%x", hardwareAssists);
    ivars->hwAssistMask = hardwareAssists;
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, GetHardwareAssists)
{
    LogI("GetHardwareAssists -> 0x%x", ivars->hwAssistMask);
    *hardwareAssists = ivars->hwAssistMask;
    return kIOReturnSuccess;
}

uint32_t
AQC111NIC::getFeatureFlags()
{
    LogI("getFeatureFlags -> 0x%x", AQC111_HWASSIST_MASK);
    return AQC111_HWASSIST_MASK;
}

kern_return_t
AQC111NIC::getTSOOptions(IOUserNetworkTSOOptions *options)
{
    if (options == nullptr) {
        return kIOReturnBadArgument;
    }
    options->tso_mtu4 = AQC111_TSO_MAX_IP_LEN;
    options->tso_mtu6 = AQC111_TSO_MAX_IP_LEN;
    LogI("getTSOOptions -> v4=%u v6=%u", options->tso_mtu4, options->tso_mtu6);
    return kIOReturnSuccess;
}

// Applies the current ivars->rxFilterBits to live hardware if the interface
// is enabled; shared by every setter that changes rxFilterBits (promiscuous,
// all-multicast, multicast hash) so they all write through one path. If the
// interface isn't up yet, the bits still take effect on the next hwOnLinkUp
// since hwOnLinkUp itself ORs in ivars->rxFilterBits (see IMPL_PLAN.md M6g).
static kern_return_t
applyRxFilterBits(AQC111NIC_IVars *ivars)
{
    if (!ivars->interfaceEnabled || ivars->interface == nullptr) {
        return kIOReturnSuccess;
    }
    uint16_t rxCtl = 0x0288 | ivars->rxFilterBits;
    kern_return_t r = aqWrite16(ivars->interface, 0x000B, rxCtl);
    LogI("applyRxFilterBits: RX_CTL=0x%04x -> 0x%x", rxCtl, r);
    return r;
}

// Shared by both the deprecated SetPromiscuousModeEnable and its modern
// lowercase replacement setPromiscuousModeEnable, since it's not yet known
// (without testing each macOS/NDK release) which one Skywalk actually calls
// — see IMPL_PLAN.md "Known Risk Points" for the M6f/M6g/M6h policy this
// follows. Toggles SFR_RX_CTL_PRO (0x0001) in the stored filter-bits ivar.
static kern_return_t
doSetPromiscuousMode(AQC111NIC_IVars *ivars, bool enable)
{
    if (enable) {
        ivars->rxFilterBits |= 0x0001u;  // SFR_RX_CTL_PRO
    } else {
        ivars->rxFilterBits &= ~0x0001u;
    }
    LogI("doSetPromiscuousMode: rxFilterBits=0x%04x (interfaceEnabled=%d)",
        ivars->rxFilterBits, ivars->interfaceEnabled);
    return applyRxFilterBits(ivars);
}

// SFR_RX_CTL_AMALL (0x0002) has two independent sources — see the
// allMulticastRequested/mcastCountExceeded ivar comment. Recomputes the bit
// as their OR every time either source changes, so the overflow trigger can
// retract on its own without disturbing an independently-active explicit
// request, and vice versa.
static void
recomputeAmallBit(AQC111NIC_IVars *ivars)
{
    if (ivars->allMulticastRequested || ivars->mcastCountExceeded) {
        ivars->rxFilterBits |= 0x0002u;  // SFR_RX_CTL_AMALL
    } else {
        ivars->rxFilterBits &= ~0x0002u;
    }
}

// Same consistency policy as doSetPromiscuousMode. See IMPL_PLAN.md M6h.
static kern_return_t
doSetAllMulticastMode(AQC111NIC_IVars *ivars, bool enable)
{
    ivars->allMulticastRequested = enable;
    recomputeAmallBit(ivars);
    LogI("doSetAllMulticastMode: requested=%d rxFilterBits=0x%04x (interfaceEnabled=%d)",
        ivars->allMulticastRequested, ivars->rxFilterBits, ivars->interfaceEnabled);
    return applyRxFilterBits(ivars);
}

// Standard reflected CRC32 (poly 0xEDB88320) — same algorithm as zlib's
// crc32/Linux's crc32_le. Used only by aqMulticastHashBit below.
static uint32_t
crc32Le(uint32_t crc, const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];
        for (int b = 0; b < 8; b++) {
            crc = (crc & 1) ? (crc >> 1) ^ 0xEDB88320u : (crc >> 1);
        }
    }
    return crc;
}

static uint32_t
bitrev32(uint32_t x)
{
    x = ((x & 0x55555555u) << 1) | ((x & 0xAAAAAAAAu) >> 1);
    x = ((x & 0x33333333u) << 2) | ((x & 0xCCCCCCCCu) >> 2);
    x = ((x & 0x0F0F0F0Fu) << 4) | ((x & 0xF0F0F0F0u) >> 4);
    x = ((x & 0x00FF00FFu) << 8) | ((x & 0xFF00FF00u) >> 8);
    return (x << 16) | (x >> 16);
}

// AQC111's multicast hash filter is a 64-bucket table (8 bytes,
// SFR_MULTI_FILTER_ARRY) indexed by the top 6 bits of
// ether_crc(mac) == bitrev32(crc32_le(~0, mac, 6)). Matches Linux
// aqc111_set_rx_mode (notes/aqc111.c:550-551) exactly — verified against a
// from-scratch port of this exact algorithm before implementing here
// (01:00:5e:7f:01:63 -> bucket 25, byte 3 bit 1).
static uint32_t
aqMulticastHashBit(const uint8_t mac[6])
{
    uint32_t crc = crc32Le(0xFFFFFFFFu, mac, 6);
    uint32_t etherCrc = bitrev32(crc);
    return etherCrc >> 26;
}

// Shared by both the deprecated SetMulticastAddresses and its modern
// lowercase replacement setMulticastAddresses. addresses is a flat array of
// count 6-byte MAC octets (IOUserNetworkMACAddress and ether_addr_t are both
// exactly { uint8_t octet[6]; }, so callers just reinterpret_cast their
// pointer). If count exceeds AQ_MAX_MCAST_ADDRESSES, falls back to AMALL
// instead of the hash table (mirrors Linux aqc111_set_rx_mode's mutual
// exclusion exactly — no point representing a partial/imprecise table when
// AMALL already admits everything). Otherwise writes the computed hash table
// to SFR_MULTI_FILTER_ARRY (not touched anywhere else, so it needs no
// re-apply-on-link-up like rxFilterBits does) and toggles SFR_RX_CTL_AM
// (0x0010) based on count > 0. See IMPL_PLAN.md M6h.
static kern_return_t
doSetMulticastAddresses(AQC111NIC_IVars *ivars, const uint8_t *addresses, uint32_t count)
{
    // Too many groups for the 64-bucket hash table to represent precisely —
    // fall back to accept-all-multicast instead (mirrors Linux's
    // mc_count > AQ_MAX_MCAST check), via the count-exceeded contribution to
    // SFR_RX_CTL_AMALL recomputed alongside any independent explicit request
    // (see allMulticastRequested/mcastCountExceeded ivar comment) — so this
    // retracts cleanly once count drops back under the threshold instead of
    // staying stuck on (confirmed reproduced as a real bug before this
    // existed — see IMPL_PLAN.md "Bug fix plan — AMALL fallback...").
    ivars->mcastCountExceeded = (count > AQ_MAX_MCAST_ADDRESSES);
    recomputeAmallBit(ivars);

    if (ivars->mcastCountExceeded) {
        LogI("doSetMulticastAddresses: count=%u exceeds max %u, falling back to AMALL",
            count, AQ_MAX_MCAST_ADDRESSES);
        return applyRxFilterBits(ivars);
    }

    uint8_t filter[8] = {};
    for (uint32_t i = 0; i < count; i++) {
        const uint8_t *mac = addresses + i * 6;
        uint32_t bit = aqMulticastHashBit(mac);
        filter[bit >> 3] |= (uint8_t)(1u << (bit & 7));
        LogI("doSetMulticastAddresses[%u]: mac=%02x:%02x:%02x:%02x:%02x:%02x hashBit=%u (byte=%u bit=%u)",
            i, mac[0], mac[1], mac[2], mac[3], mac[4], mac[5],
            bit, bit >> 3, bit & 7);
    }

    kern_return_t r = kIOReturnSuccess;
    if (ivars->interface != nullptr) {
        r = aqWrite(ivars->interface, 0x0016, filter, sizeof(filter));  // SFR_MULTI_FILTER_ARRY
        LogI("doSetMulticastAddresses: count=%u filter=%02x %02x %02x %02x %02x %02x %02x %02x -> 0x%x",
            count, filter[0], filter[1], filter[2], filter[3],
            filter[4], filter[5], filter[6], filter[7], r);
    }

    if (count > 0) {
        ivars->rxFilterBits |= 0x0010u;  // SFR_RX_CTL_AM
    } else {
        ivars->rxFilterBits &= ~0x0010u;
    }
    kern_return_t r2 = applyRxFilterBits(ivars);
    return (r != kIOReturnSuccess) ? r : r2;
}

// --- Dispatched overrides ---

// M11 phase 0 PM transparency: pure observation, no behavior change — logs
// which power transitions the NIC personality receives across system
// sleep/wake, and how they order against SetInterfaceEnable/Stop/USB
// completions (the undocumented layer M11 WoL arming depends on; also
// diagnostic infra for the RX-stall-on-sleep/wake incident). Decode:
// 0x0=Off(system sleep) 0x2=On 0x10000=Low 0x20000=LPW.
kern_return_t
IMPL(AQC111NIC, SetPowerState)
{
    switch (powerFlags) {
    case kIOServicePowerCapabilityOff: ivars->pmOffCount++;   break;
    case kIOServicePowerCapabilityOn:  ivars->pmOnCount++;    break;
    case kIOServicePowerCapabilityLow: ivars->pmLowCount++;   break;
    default:                           ivars->pmOtherCount++; break;
    }
    LogI("SetPowerState: powerFlags=0x%x (%{public}s) [off=%u on=%u low=%u other=%u]",
        powerFlags,
        powerFlags == kIOServicePowerCapabilityOff ? "Off/sleep" :
        powerFlags == kIOServicePowerCapabilityOn  ? "On" :
        powerFlags == kIOServicePowerCapabilityLow ? "Low" : "other",
        ivars->pmOffCount, ivars->pmOnCount, ivars->pmLowCount, ivars->pmOtherCount);
    return SetPowerState(powerFlags, SUPERDISPATCH);
}

// TODO: SetInterfaceEnable is the deprecated capital form (IOUserNetworkEthernet.iig:
// "@deprecated, use setInterfaceEnable instead"); the lowercase setInterfaceEnable
// (LOCALONLY NDK_21) is the documented modern replacement. Confirmed empirically this
// whole project that the OS calls the deprecated form on this NDK (every ifconfig
// up/down logs here), so this is not currently broken — but for consistency with the
// "implement both, one shared helper" policy adopted for promiscuous/multicast (see
// IMPL_PLAN.md M6g/M6h), setInterfaceEnable should eventually forward to the same
// logic too, in case a future macOS/NDK release switches which one Skywalk calls.
kern_return_t
IMPL(AQC111NIC, SetInterfaceEnable)
{
    LogI("SetInterfaceEnable: %d", isEnable);
    if (isEnable) {
        // If a previous enable cycle left USB I/O armed (no intervening
        // disable), tear it down before bringing the PHY back up.
        if (ivars->ioArmed) {
            ensureRxStopped(ivars);
            disarmAsyncIO(ivars);
            hwDisable(ivars->interface);
        }

        // ClearStall every pipe — safe on fresh pipes, required after Abort.
        if (ivars->pipeItr) {
            kern_return_t r = ivars->pipeItr->ClearStall(false);
            LogI("SetInterfaceEnable: ClearStall ITR -> 0x%x", r);
        }
        if (ivars->pipeRx) {
            kern_return_t r = ivars->pipeRx->ClearStall(false);
            LogI("SetInterfaceEnable: ClearStall RX -> 0x%x", r);
        }
        if (ivars->pipeTx) {
            kern_return_t r = ivars->pipeTx->ClearStall(false);
            LogI("SetInterfaceEnable: ClearStall TX -> 0x%x", r);
        }

        ivars->interfaceEnabled = true;

        kern_return_t r;
        r = ivars->txsQueue->SetEnable(true); LogI("SetInterfaceEnable: txsQueue SetEnable -> 0x%x", r);
        r = ivars->txcQueue->SetEnable(true); LogI("SetInterfaceEnable: txcQueue SetEnable -> 0x%x", r);
        r = ivars->rxsQueue->SetEnable(true); LogI("SetInterfaceEnable: rxsQueue SetEnable -> 0x%x", r);
        r = ivars->rxcQueue->SetEnable(true); LogI("SetInterfaceEnable: rxcQueue SetEnable -> 0x%x", r);

        // PHY bring-up MUST precede armAsyncIO. See notes/itr_ordering_analysis.md.
        // Posting ITR before hwEnable causes the first URB completion to capture
        // a stale autoneg-in-progress state; the device may not re-signal once
        // autoneg actually completes, leaving the interface stuck "inactive"
        // until a physical cable transition.
        hwEnable(ivars->interface, ivars->macAddress, ivars->phyAdvertiseMask);

        kern_return_t armRet = armAsyncIO(ivars);
        LogI("SetInterfaceEnable: armAsyncIO -> 0x%x", armRet);
        LogI("pmCounters at enable: off=%u on=%u low=%u other=%u",
            ivars->pmOffCount, ivars->pmOnCount, ivars->pmLowCount, ivars->pmOtherCount);
    } else {
        ivars->interfaceEnabled = false;
        ensureRxStopped(ivars);
        disarmAsyncIO(ivars);
        hwDisable(ivars->interface);

        kern_return_t r;
        r = ivars->rxcQueue->SetEnable(false); LogI("SetInterfaceEnable: rxcQueue SetEnable(false) -> 0x%x", r);
        r = ivars->rxsQueue->SetEnable(false); LogI("SetInterfaceEnable: rxsQueue SetEnable(false) -> 0x%x", r);
        r = ivars->txcQueue->SetEnable(false); LogI("SetInterfaceEnable: txcQueue SetEnable(false) -> 0x%x", r);
        r = ivars->txsQueue->SetEnable(false); LogI("SetInterfaceEnable: txsQueue SetEnable(false) -> 0x%x", r);

        IOReturn lsRet = reportLinkStatus(kIOUserNetworkLinkStatusInactive, kIOUserNetworkMediaEthernetAuto);
        LogI("SetInterfaceEnable: reportLinkStatus(inactive, Auto) -> 0x%x", lsRet);
    }
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetPromiscuousModeEnable)
{
    LogI("SetPromiscuousModeEnable: %d", enable);
    return doSetPromiscuousMode(ivars, enable);
}

kern_return_t
AQC111NIC::setPromiscuousModeEnable(bool enable)
{
    LogI("setPromiscuousModeEnable (lowercase): %d", enable);
    return doSetPromiscuousMode(ivars, enable);
}

kern_return_t
IMPL(AQC111NIC, SetAllMulticastModeEnable)
{
    LogI("SetAllMulticastModeEnable: %d", enable);
    return doSetAllMulticastMode(ivars, enable);
}

kern_return_t
AQC111NIC::setAllMulticastModeEnable(bool enable)
{
    LogI("setAllMulticastModeEnable (lowercase): %d", enable);
    return doSetAllMulticastMode(ivars, enable);
}

kern_return_t
IMPL(AQC111NIC, SetMulticastAddresses)
{
    LogI("SetMulticastAddresses: count=%u", count);
    return doSetMulticastAddresses(ivars, reinterpret_cast<const uint8_t *>(addresses), count);
}

kern_return_t
AQC111NIC::setMulticastAddresses(const ether_addr_t *addresses, uint32_t count)
{
    LogI("setMulticastAddresses (lowercase): count=%u", count);
    return doSetMulticastAddresses(ivars, reinterpret_cast<const uint8_t *>(addresses), count);
}

// TODO: SelectMediaType is the deprecated capital form ("@deprecated, use
// handleChosenMedia instead"). Confirmed empirically (2026-06-23, IMPL_PLAN.md M6f)
// that the OS actually calls handleChosenMedia for ifconfig media changes, not this
// one — left as a no-op stub deliberately. For consistency with the "implement both,
// one shared helper" policy adopted for promiscuous/multicast (IMPL_PLAN.md M6g/M6h),
// this should eventually forward to the same logic handleChosenMedia uses, in case
// some caller still invokes this legacy path.
kern_return_t
IMPL(AQC111NIC, SelectMediaType)
{
    LogI("SelectMediaType: 0x%x", mediaType);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetWakeOnMagicPacketEnable)
{
    LogI("SetWakeOnMagicPacketEnable: %d", enable);
    return kIOReturnSuccess;
}

kern_return_t
AQC111NIC::getHardwareAddress(ether_addr_t *addr)
{
    LogI("getHardwareAddress: called, cached=%02x:%02x:%02x:%02x:%02x:%02x",
        ivars->macAddress.octet[0], ivars->macAddress.octet[1], ivars->macAddress.octet[2],
        ivars->macAddress.octet[3], ivars->macAddress.octet[4], ivars->macAddress.octet[5]);
    if (addr == nullptr) {
        return kIOReturnBadArgument;
    }
    memcpy(addr->octet, ivars->macAddress.octet, 6);
    return kIOReturnSuccess;
}

kern_return_t
AQC111NIC::setHardwareAddress(ether_addr_t *addr)
{
    LogI("setHardwareAddress: called");
    if (addr == nullptr) {
        return kIOReturnBadArgument;
    }
    LogI("setHardwareAddress: requested %02x:%02x:%02x:%02x:%02x:%02x",
        addr->octet[0], addr->octet[1], addr->octet[2],
        addr->octet[3], addr->octet[4], addr->octet[5]);

    kern_return_t ret = aqWrite(ivars->interface, 0x0010, addr->octet, 6);
    LogI("setHardwareAddress: write SFR_NODE_ID -> 0x%x", ret);
    if (ret != kIOReturnSuccess) {
        return ret;
    }
    memcpy(ivars->macAddress.octet, addr->octet, 6);
    return kIOReturnSuccess;
}

// --- Media support ---

kern_return_t
AQC111NIC::getSupportedMediaArray(MediaWord *mediaArray, uint32_t *mediaCount)
{
    LogI("getSupportedMediaArray");
    static const uint32_t opts = kIOUserNetworkMediaOptionFullDuplex |
                                 kIOUserNetworkMediaOptionFlowControl;
    static const MediaWord kMedia[] = {
        kIOUserNetworkMediaEthernetAuto,
        kIOUserNetworkMediaEthernet100BaseTX | opts,
        kIOUserNetworkMediaEthernet1000BaseT | opts,
        kIOUserNetworkMediaEthernet2500BaseT | opts,
        kIOUserNetworkMediaEthernet5000BaseT | opts,
    };
    const uint32_t count = sizeof(kMedia) / sizeof(kMedia[0]);
    for (uint32_t i = 0; i < count; i++) {
        mediaArray[i] = kMedia[i];
    }
    *mediaCount = count;
    return kIOReturnSuccess;
}

kern_return_t
AQC111NIC::handleChosenMedia(MediaWord chosenMedia)
{
    LogI("handleChosenMedia: 0x%x", chosenMedia);

    // Hardware only supports full duplex at every rate it advertises (matches
    // Linux aqc111_set_link_ksettings's explicit DUPLEX_FULL-only check) — no
    // forced-half-duplex mode exists to map this onto.
    if (chosenMedia & kIOUserNetworkMediaOptionHalfDuplex) {
        LogE("handleChosenMedia: half-duplex requested, unsupported");
        return kIOReturnUnsupported;
    }

    MediaWord baseType = chosenMedia & kIOUserNetworkMediaEthernetMask;
    uint32_t advertiseMask;
    switch (baseType) {
    case kIOUserNetworkMediaEthernetAuto:
    case kIOUserNetworkMediaEthernetNone:
    case kIOUserNetworkMediaEthernetManual:
        advertiseMask = 0x0000000Fu;  // AQ_ADV_MASK: autoneg all rates
        break;
    case kIOUserNetworkMediaEthernet100BaseTX:
        advertiseMask = 0x1u;  // AQ_ADV_100M only — force this rate
        break;
    case kIOUserNetworkMediaEthernet1000BaseT:
        advertiseMask = 0x2u;  // AQ_ADV_1G only
        break;
    case kIOUserNetworkMediaEthernet2500BaseT:
        advertiseMask = 0x4u;  // AQ_ADV_2G5 only
        break;
    case kIOUserNetworkMediaEthernet5000BaseT:
        advertiseMask = 0x8u;  // AQ_ADV_5G only
        break;
    default:
        LogE("handleChosenMedia: unsupported media type 0x%x", baseType);
        return kIOReturnUnsupported;
    }

    ivars->phyAdvertiseMask = advertiseMask;
    LogI("handleChosenMedia: advertiseMask=0x%x (interfaceEnabled=%d)",
        advertiseMask, ivars->interfaceEnabled);

    // Apply live if the interface is already up; otherwise the stored mask
    // takes effect on the next hwEnable (ifconfig up).
    if (ivars->interfaceEnabled && ivars->interface != nullptr) {
        kern_return_t ret = applyPhyAdvertise(ivars->interface, advertiseMask);
        return ret;
    }
    return kIOReturnSuccess;
}

MediaWord
AQC111NIC::getInitialMedia()
{
    LogI("getInitialMedia");
    return kIOUserNetworkMediaEthernetAuto;
}

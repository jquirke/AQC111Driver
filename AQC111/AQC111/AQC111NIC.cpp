
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

#define Log(fmt, ...) os_log(OS_LOG_DEFAULT, "AQC111-NIC [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__)

// Endpoint addresses for Config 1 vendor interface (class 0xFF)
#define EP_ITR  0x81   // EP1 IN  Interrupt 16B  — link status
#define EP_RX   0x82   // EP2 IN  Bulk 1024B     — receive
#define EP_TX   0x03   // EP3 OUT Bulk 1024B     — transmit

// RX ring — 10 outstanding USB bulk IN transfers, each 64KB.
// Device aggregates multiple Ethernet frames per transfer.
#define RX_SLOTS        10
#define RX_BUF_SIZE     0x10000   // 64KB per slot

static kern_return_t aqWrite(IOUSBHostInterface *iface, uint16_t addr, const void *data, uint16_t len);
static kern_return_t aqRead(IOUSBHostInterface *iface, uint16_t addr, void *data, uint16_t len);
static kern_return_t aqVendorOut(IOUSBHostInterface *iface, uint8_t request, const void *data, uint16_t len);
static void disarmAsyncIO(struct AQC111NIC_IVars *ivars);
static void hwDisable(IOUSBHostInterface *iface);
static void hwOnLinkUp(IOUSBHostInterface *iface, uint8_t speedCode);
static void hwOnLinkDown(IOUSBHostInterface *iface);
static void ensureRxStarted(struct AQC111NIC_IVars *ivars, uint8_t speedCode);
static void ensureRxStopped(struct AQC111NIC_IVars *ivars);
static void resetEnablePath(struct AQC111NIC_IVars *ivars);
static void dumpRxBytes(const uint8_t *buf, uint32_t actualByteCount, uint32_t slot, IOReturn status);
struct RxParseInfo {
    uint32_t headerOffset;
    uint32_t packetBaseOffset;
    uint32_t descriptorOffset;
    uint32_t packetCount;
};
static bool parseRxLayout(const uint8_t *buf, uint32_t actualByteCount, RxParseInfo *info);
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

struct AQC111NIC_IVars {
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
    bool                                lastLinkUp;
    bool                                interfaceEnabled;
    bool                                rxStarted;
    bool                                ioArmed;
    IOUserNetworkMACAddress             macAddress;
    // Dext-owned queue for OSAction callbacks (timer, USB async IO).
    // CopyDispatchQueue("Default") returns the kernel-side networking proxy queue
    // which doesn't deliver OSAction callbacks into our process.
    IODispatchQueue                    *asyncQueue;
    // OSAction dispatch diagnostic
    IOTimerDispatchSource              *timerTest;
    OSAction                           *timerAction;
    bool                                dumpedRx80;
    bool                                dumpedRx432;
    bool                                dumpedRxOther;
};

bool
AQC111NIC::init()
{
    if (!super::init()) return false;
    ivars = IONewZero(AQC111NIC_IVars, 1);
    return ivars != nullptr;
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

    Log("Start ENTERED: provider=%p", provider);

    ret = Start(provider, SUPERDISPATCH);
    Log("Start: super -> 0x%x", ret);
    if (ret != kIOReturnSuccess) {
        Log("Start: super FAILED");
        return ret;
    }
    Log("Start: super OK");

    // Create a dext-owned queue for Skywalk RxDispatchQueue/TxDispatchQueue slots.
    // IIG's AQC111NIC_QueueNames registers these two names; SetDispatchQueue binds them.
    // "Default" is intentionally NOT overridden — it is a framework-installed proxy queue
    // with hidden internal structure that Stop_Impl's async cancel completion depends on.
    // Replacing "Default" causes a null+0x10 crash in Stop_Impl's teardown block.
    ret = IODispatchQueue::Create("AQC111.async", 0, 0, &ivars->asyncQueue);
    Log("Start: asyncQueue create -> 0x%x queue=%p", ret, ivars->asyncQueue);
    if (ret != kIOReturnSuccess) goto fail;

    ret = SetDispatchQueue("RxDispatchQueue", ivars->asyncQueue);
    Log("Start: SetDispatchQueue(RxDispatchQueue) -> 0x%x", ret);
    if (ret != kIOReturnSuccess) goto fail;

    ret = SetDispatchQueue("TxDispatchQueue", ivars->asyncQueue);
    Log("Start: SetDispatchQueue(TxDispatchQueue) -> 0x%x", ret);
    if (ret != kIOReturnSuccess) goto fail;

    // Provider is IOUSBHostInterface — Config 1, bInterfaceClass=255.
    // Config 1 is already pinned by Personality A (AQC111 device personality).
    ivars->interface = OSDynamicCast(IOUSBHostInterface, provider);
    if (ivars->interface == nullptr) {
        Log("Start: provider is not IOUSBHostInterface");
        goto fail;
    }

    // Get device for control transfers (bRequest=0x01/0x20/0x61).
    // Personality A already holds it open; we open a second session to
    // ensure Config 1 stays pinned even if A tears down before we do.
    // Get device reference for control transfers. Personality A (AQC111) already
    // holds the exclusive open session; we must NOT call Open() again.
    ret = ivars->interface->CopyDevice(&ivars->device);
    if (ret != kIOReturnSuccess || ivars->device == nullptr) {
        Log("Start: CopyDevice failed: 0x%x", ret);
        goto fail;
    }
    Log("Start: CopyDevice OK device=%p", ivars->device);

    // Open our provider interface. No SetConfiguration needed — already done.
    ret = ivars->interface->Open(this, 0, nullptr);
    if (ret != kIOReturnSuccess) {
        Log("Start: interface Open failed: 0x%x", ret);
        goto fail;
    }
    Log("Start: interface open");

    // Read permanent MAC address from EEPROM (AQ_FLASH_PARAMETERS, bRequest=0x20).
    {
        kern_return_t macRet = readMACAddress(ivars->interface, &macAddress);
        Log("Start: readMAC -> 0x%x  %02x:%02x:%02x:%02x:%02x:%02x",
            macRet,
            macAddress.octet[0], macAddress.octet[1], macAddress.octet[2],
            macAddress.octet[3], macAddress.octet[4], macAddress.octet[5]);
        if (macRet != kIOReturnSuccess) {
            macAddress = { .octet = { 0x02, 0xAC, 0x11, 0x11, 0x00, 0x01 } };
        }
        ivars->macAddress = macAddress;

        kern_return_t nodeRet = aqWrite(ivars->interface, 0x0010, ivars->macAddress.octet, 6);
        Log("Start: write SFR_NODE_ID -> 0x%x", nodeRet);
        uint8_t readback[6] = {};
        kern_return_t rbRet = aqRead(ivars->interface, 0x0010, readback, 6);
        Log("Start: read  SFR_NODE_ID -> 0x%x  %02x:%02x:%02x:%02x:%02x:%02x",
            rbRet,
            readback[0], readback[1], readback[2],
            readback[3], readback[4], readback[5]);
    }

    ret = ivars->interface->CopyPipe(EP_ITR, &ivars->pipeItr);
    Log("Start: CopyPipe(ITR) -> 0x%x pipe=%p", ret, ivars->pipeItr);
    if (ret != kIOReturnSuccess || ivars->pipeItr == nullptr) goto fail;

    ret = ivars->interface->CopyPipe(EP_RX, &ivars->pipeRx);
    Log("Start: CopyPipe(RX)  -> 0x%x pipe=%p", ret, ivars->pipeRx);
    if (ret != kIOReturnSuccess || ivars->pipeRx == nullptr) goto fail;

    ret = ivars->interface->CopyPipe(EP_TX, &ivars->pipeTx);
    Log("Start: CopyPipe(TX)  -> 0x%x pipe=%p", ret, ivars->pipeTx);
    if (ret != kIOReturnSuccess || ivars->pipeTx == nullptr) goto fail;

    if (ivars->pipeItr) {
        kern_return_t csRet = ivars->pipeItr->ClearStall(false);
        Log("Start: ClearStall(ITR) -> 0x%x", csRet);
    }
    if (ivars->pipeRx) {
        kern_return_t csRet = ivars->pipeRx->ClearStall(false);
        Log("Start: ClearStall(RX) -> 0x%x", csRet);
    }

    // --- Networking setup ---

    ret = CopyDispatchQueue("Default", &ivars->queue);
    if (ret != kIOReturnSuccess) {
        Log("Start: CopyDispatchQueue failed: 0x%x", ret);
        goto fail;
    }

    poolOptions.packetCount = 64;
    poolOptions.bufferCount = 64;
    poolOptions.bufferSize  = 2048;
    poolOptions.maxBuffersPerPacket = 1;
    poolOptions.memorySegmentSize = 0;
    poolOptions.poolFlags = PoolFlagMapToDext;
    poolOptions.dmaSpecification.maxAddressBits = 64;
    ret = IOUserNetworkPacketBufferPool::CreateWithOptions(
        this, "AQC111", &poolOptions, &ivars->pool);
    if (ret != kIOReturnSuccess) {
        Log("Start: CreatePacketBufferPool failed: 0x%x", ret);
        goto fail;
    }

    ret = IOUserNetworkTxSubmissionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->txsQueue);
    if (ret != kIOReturnSuccess) { Log("Start: TxSubmission failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkTxCompletionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->txcQueue);
    if (ret != kIOReturnSuccess) { Log("Start: TxCompletion failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkRxSubmissionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->rxsQueue);
    if (ret != kIOReturnSuccess) { Log("Start: RxSubmission failed: 0x%x", ret); goto fail; }

    ret = IOUserNetworkRxCompletionQueue::Create(
        ivars->pool, this, 16, 0, ivars->queue, &ivars->rxcQueue);
    if (ret != kIOReturnSuccess) { Log("Start: RxCompletion failed: 0x%x", ret); goto fail; }

    queues[0] = ivars->txsQueue;
    queues[1] = ivars->txcQueue;
    queues[2] = ivars->rxsQueue;
    queues[3] = ivars->rxcQueue;

    ret = RegisterEthernetInterface(macAddress, ivars->pool, queues, 4);
    if (ret != kIOReturnSuccess) {
        Log("Start: RegisterEthernetInterface failed: 0x%x", ret);
        goto fail;
    }
    Log("Start: RegisterEthernetInterface OK");

    // Post 10 outstanding RX bulk IN transfers.
    for (int i = 0; i < RX_SLOTS; i++) {
        ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionIn, RX_BUF_SIZE, 0, &ivars->rxBufs[i]);
        if (ret != kIOReturnSuccess) {
            Log("Start: rxBuf[%d] alloc failed: 0x%x", i, ret);
            goto fail;
        }
        ret = CreateActionOnRxComplete(sizeof(uint32_t), &ivars->rxActions[i]);
        if (ret != kIOReturnSuccess) {
            Log("Start: rxAction[%d] create failed: 0x%x", i, ret);
            goto fail;
        }
        *(uint32_t *)ivars->rxActions[i]->GetReference() = (uint32_t)i;

        ret = ivars->pipeRx->AsyncIO(ivars->rxBufs[i], RX_BUF_SIZE, ivars->rxActions[i], 0);
        if (ret != kIOReturnSuccess) {
            Log("Start: rxAsyncIO[%d] failed: 0x%x", i, ret);
            goto fail;
        }
    }
    Log("Start: %d RX transfers posted", RX_SLOTS);

    // Post one ITR (interrupt IN) transfer for link-status events.
    ret = IOBufferMemoryDescriptor::Create(kIOMemoryDirectionIn, 16, 0, &ivars->itrBuf);
    if (ret != kIOReturnSuccess) {
        Log("Start: itrBuf alloc failed: 0x%x", ret);
        goto fail;
    }
    ret = CreateActionOnItrComplete(0, &ivars->itrAction);
    if (ret != kIOReturnSuccess) {
        Log("Start: itrAction create failed: 0x%x", ret);
        goto fail;
    }
    ret = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
    if (ret != kIOReturnSuccess) {
        Log("Start: itrAsyncIO failed: 0x%x", ret);
        goto fail;
    }
    ivars->ioArmed = true;
    Log("Start: ITR transfer posted");

    reportLinkStatus(kIOUserNetworkLinkStatusInactive, kIOUserNetworkMediaEthernetAuto);

    ret = RegisterService();
    Log("Start: RegisterService -> 0x%x", ret);

    // --- OSAction dispatch diagnostic ---
    // If OnTimerFired fires ~3s after start, OSAction dispatch works on this
    // provider shape. Expected to fire now that provider is IOUSBHostInterface.
    {
        kern_return_t tr = IOTimerDispatchSource::Create(ivars->queue, &ivars->timerTest);
        if (tr == kIOReturnSuccess) {
            tr = CreateActionOnTimerFired(0, &ivars->timerAction);
        }
        if (tr == kIOReturnSuccess) {
            tr = ivars->timerTest->SetHandler(ivars->timerAction);
            Log("Start: timer SetHandler -> 0x%x", tr);
            if (tr == kIOReturnSuccess) tr = ivars->timerTest->SetEnable(true);
            Log("Start: timer SetEnable -> 0x%x", tr);
        }
        if (tr == kIOReturnSuccess) {
            uint64_t fireAt = clock_gettime_nsec_np(CLOCK_UPTIME_RAW) + 3ULL * 1000000000ULL;
            kern_return_t wr = ivars->timerTest->WakeAtTime(kIOTimerClockUptimeRaw, fireAt, 0);
            Log("Start: timer WakeAtTime -> 0x%x (fires in ~3s)", wr);
        } else {
            Log("Start: timer setup failed: 0x%x", tr);
        }
    }

    return ret;

fail:
    Stop(provider, SUPERDISPATCH);
    return kIOReturnError;
}

kern_return_t
IMPL(AQC111NIC, Stop)
{
    Log("Stop: enter");
    ivars->interfaceEnabled = false;
    ivars->ioArmed = false;

    // DispatchSync removed: during force-close/uninstall asyncQueue may not
    // be serviceable, causing DispatchSync to block indefinitely and
    // preventing SUPERDISPATCH from ever being called. Instead: cancel timer
    // and abort pipes directly, then close interface.

    // Cancel timer directly (no queue serialisation needed — timer is
    // one-shot and either already fired or idle by this point).
    if (ivars->timerTest != nullptr) {
        kern_return_t r = ivars->timerTest->Cancel(nullptr);
        Log("Stop: Cancel timer -> 0x%x", r);
    }

    // Abort pipes synchronously before closing the interface.
    // kIOUSBAbortSynchronous ensures completions have fired before returning.
    if (ivars->pipeItr != nullptr) {
        kern_return_t r = ivars->pipeItr->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        Log("Stop: Abort ITR -> 0x%x", r);
    }
    if (ivars->pipeRx != nullptr) {
        kern_return_t r = ivars->pipeRx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        Log("Stop: Abort RX -> 0x%x", r);
    }
    if (ivars->pipeTx != nullptr) {
        kern_return_t r = ivars->pipeTx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        Log("Stop: Abort TX -> 0x%x", r);
    }

    if (ivars->interface != nullptr) {
        kern_return_t r = ivars->interface->Close(this, 0);
        Log("Stop: Close interface -> 0x%x", r);
    }

    Log("Stop: releasing objects");
    OSSafeReleaseNULL(ivars->timerAction);
    OSSafeReleaseNULL(ivars->timerTest);
    OSSafeReleaseNULL(ivars->itrAction);
    OSSafeReleaseNULL(ivars->itrBuf);
    for (int i = 0; i < RX_SLOTS; i++) {
        OSSafeReleaseNULL(ivars->rxActions[i]);
        OSSafeReleaseNULL(ivars->rxBufs[i]);
    }
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

    Log("Stop: before SUPERDISPATCH");
    kern_return_t ret = Stop(provider, SUPERDISPATCH);
    Log("Stop: after SUPERDISPATCH ret=0x%x", ret);
    return ret;
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
armAsyncIO(AQC111NIC_IVars *ivars)
{
    kern_return_t ret;

    if (ivars->ioArmed) {
        return kIOReturnSuccess;
    }

    for (int i = 0; i < RX_SLOTS; i++) {
        ret = ivars->pipeRx->AsyncIO(ivars->rxBufs[i], RX_BUF_SIZE, ivars->rxActions[i], 0);
        Log("armAsyncIO: RX[%d] -> 0x%x", i, ret);
        if (ret != kIOReturnSuccess) {
            return ret;
        }
    }

    ret = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
    Log("armAsyncIO: ITR -> 0x%x", ret);
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
        Log("disarmAsyncIO: Abort ITR -> 0x%x", r);
    }
    if (ivars->pipeRx != nullptr) {
        r = ivars->pipeRx->Abort(kIOUSBAbortSynchronous, kIOReturnAborted, nullptr);
        Log("disarmAsyncIO: Abort RX -> 0x%x", r);
    }
}

// Minimal PHY-only bring-up sequence derived from Linux aqc111.c and the x86
// IOKit RE notes. This intentionally does not enable RX or program the final
// medium state; that belongs on the link-up path once the PHY is alive.
static void
hwEnable(IOUSBHostInterface *iface, const IOUserNetworkMACAddress &mac)
{
    kern_return_t ret;
    uint8_t  b;
    uint16_t w;
    uint32_t phyFlags;

    // RE note: the x86 driver exits PHY low-power before advertisement.
    // We do not have the MDIO helper path wired up yet, so perform the steps
    // we can map directly first: explicit PHY power-on and stateful advertise.
    b = 0x02;
    ret = aqVendorOut(iface, 0x31, &b, 1);
    Log("hwEnable: AQ_PHY_POWER=0x02 -> 0x%x", ret);

    ret = aqWrite(iface, 0x0010, mac.octet, 6);
    Log("hwEnable: SFR_NODE_ID -> 0x%x", ret);

    b = 0xFF;
    ret = aqWrite(iface, 0x0041, &b, 1);
    Log("hwEnable: BM_INT_MASK=0xFF -> 0x%x", ret);

    // Mirror the x86 driver's pre-advertise state clears before asking the PHY
    // to negotiate. These clear MAC/path bits that should not remain latched
    // across bring-up attempts.
    b = 0x00;
    ret = aqWrite(iface, 0x00B1, &b, 1);
    Log("hwEnable: reg[0x00B1]=0x00 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x0024, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= 0xE0;
        ret = aqWrite(iface, 0x0024, &b, 1);
    }
    Log("hwEnable: reg[0x0024]&=0xE0 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x000B, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= (uint8_t)~0x80;
        ret = aqWrite(iface, 0x000B, &b, 1);
    }
    Log("hwEnable: reg[0x000B] clear bit7 -> 0x%x", ret);

    w = 0;
    ret = aqRead(iface, 0x0022, &w, 2);
    if (ret == kIOReturnSuccess) {
        w &= (uint16_t)~0x0100;
        ret = aqWrite(iface, 0x0022, &w, 2);
    }
    Log("hwEnable: reg[0x0022] clear bit8 -> 0x%x", ret);

    b = 0;
    ret = aqRead(iface, 0x00B0, &b, 1);
    if (ret == kIOReturnSuccess) {
        b &= (uint8_t)~0x01;
        ret = aqWrite(iface, 0x00B0, &b, 1);
    }
    Log("hwEnable: reg[0x00B0] clear bit0 -> 0x%x", ret);

    // AQ_PHY_OPS takes the little-endian MediumFlags dword, not a hardcoded
    // 4-byte literal. Match the Linux/x86 model: advertise all rates, pause,
    // asym pause, PHY power enabled, downshift enabled, retries=7.
    phyFlags = 0;
    phyFlags |= 0x0000000Fu;  // AQ_ADV_MASK: 100M, 1G, 2.5G, 5G
    phyFlags |= 1u << 16;     // AQ_PAUSE
    phyFlags |= 1u << 17;     // AQ_ASYM_PAUSE
    phyFlags |= 1u << 19;     // AQ_PHY_POWER_EN
    phyFlags |= 1u << 21;     // AQ_DOWNSHIFT
    phyFlags |= 7u << 24;     // AQ_DSH_RETRIES default
    ret = aqVendorOut(iface, 0x61, &phyFlags, sizeof(phyFlags));
    Log("hwEnable: AQ_PHY_OPS flags=0x%08x -> 0x%x", phyFlags, ret);

    b = 0x01;
    ret = aqWrite(iface, 0x00B7, &b, 1);
    Log("hwEnable: ETH_MAC_PATH=0x01 -> 0x%x", ret);

    b = 0x02;
    ret = aqWrite(iface, 0x00B9, &b, 1);
    Log("hwEnable: BULK_OUT_CTRL=0x02 -> 0x%x", ret);

    uint8_t coalesce[5] = { 0x07, 0x00, 0x01, 0x1E, 0xFF };
    ret = aqWrite(iface, 0x002E, coalesce, 5);
    Log("hwEnable: coalescing -> 0x%x", ret);
}

static void
hwOnLinkUp(IOUSBHostInterface *iface, uint8_t speedCode)
{
    kern_return_t r;
    uint16_t rxCtl;
    uint16_t medium;
    uint8_t b;
    uint8_t coalesce[5] = { 0x07, 0x00, 0x01, 0x1E, 0xFF };

    // Mirror the Linux/x86 receive-start sequence on actual link-up.
    rxCtl = 0x0000;
    r = aqWrite(iface, 0x000B, &rxCtl, 2);
    Log("hwOnLinkUp: RX_CTL=0x0000 -> 0x%x", r);

    b = 0x01;
    r = aqWrite(iface, 0x00B7, &b, 1);
    Log("hwOnLinkUp: ETH_MAC_PATH=0x01 -> 0x%x", r);

    b = 0x02;
    r = aqWrite(iface, 0x00B9, &b, 1);
    Log("hwOnLinkUp: BULK_OUT_CTRL=0x02 -> 0x%x", r);

    if (speedCode == 0x13) {
        coalesce[1] = 0xA0;
        coalesce[2] = 0x00;
        coalesce[3] = 0x14;
        coalesce[4] = 0x00;
    }
    r = aqWrite(iface, 0x002E, coalesce, sizeof(coalesce));
    Log("hwOnLinkUp: coalescing(speed=0x%02x) -> 0x%x", speedCode, r);

    medium = 0x0002 | 0x0010 | 0x0020;  // full duplex + RX/TX flow control
    if (speedCode == 0x0F || speedCode == 0x10) {
        medium |= 0x0001;  // XGMIIMODE for 5G / 2.5G
    }
    r = aqWrite(iface, 0x0022, &medium, 2);
    Log("hwOnLinkUp: MEDIUM_STATUS_MODE=0x%04x -> 0x%x", medium, r);

    medium |= 0x0100;  // RECEIVE_EN
    r = aqWrite(iface, 0x0022, &medium, 2);
    Log("hwOnLinkUp: MEDIUM_STATUS_MODE|=RECEIVE_EN => 0x%04x -> 0x%x", medium, r);

    b = 0x10;  // SFR_VLAN_CONTROL_VSO
    r = aqWrite(iface, 0x002B, &b, 1);
    Log("hwOnLinkUp: VLAN_ID_CONTROL=0x10 -> 0x%x", r);

    // The x86 path also touches speed-dependent secondary controls here
    // (0x0046, 0x009e). Keep this patch minimal and focus first on the
    // must-have RX producer enables.
    rxCtl = 0x0288;  // default hwSetFilters: IPE | START | AB
    r = aqWrite(iface, 0x000B, &rxCtl, 2);
    Log("hwOnLinkUp: RX_CTL=0x%04x -> 0x%x", rxCtl, r);
}

static void
hwOnLinkDown(IOUSBHostInterface *iface)
{
    kern_return_t r;
    uint16_t rxCtl;
    uint16_t medium;

    rxCtl = 0x0000;
    r = aqWrite(iface, 0x000B, &rxCtl, 2);
    Log("hwOnLinkDown: RX_CTL=0x0000 -> 0x%x", r);

    medium = 0;
    r = aqRead(iface, 0x0022, &medium, 2);
    Log("hwOnLinkDown: read MEDIUM_STATUS_MODE -> 0x%x val=0x%04x", r, medium);
    if (r == kIOReturnSuccess) {
        medium &= (uint16_t)~0x0100;
        r = aqWrite(iface, 0x0022, &medium, 2);
    }
    Log("hwOnLinkDown: MEDIUM_STATUS_MODE&=~RECEIVE_EN => 0x%04x -> 0x%x", medium, r);
}

static void
ensureRxStarted(AQC111NIC_IVars *ivars, uint8_t speedCode)
{
    if (ivars == nullptr || !ivars->interfaceEnabled) {
        return;
    }
    if (ivars->rxStarted) {
        Log("ensureRxStarted: already started");
        return;
    }
    hwOnLinkUp(ivars->interface, speedCode);
    ivars->rxStarted = true;
    Log("ensureRxStarted: started speed=0x%02x", speedCode);
}

static void
ensureRxStopped(AQC111NIC_IVars *ivars)
{
    if (ivars == nullptr) {
        return;
    }
    if (!ivars->rxStarted) {
        Log("ensureRxStopped: already stopped");
        return;
    }
    hwOnLinkDown(ivars->interface);
    ivars->rxStarted = false;
    Log("ensureRxStopped: stopped");
}

static void
resetEnablePath(AQC111NIC_IVars *ivars)
{
    if (ivars == nullptr) {
        return;
    }

    // `ifconfig up` needs to be strong enough to recreate the transient RX-working
    // state seen earlier, not just leave previously armed USB state in place.
    ensureRxStopped(ivars);
    disarmAsyncIO(ivars);
    hwDisable(ivars->interface);

    if (ivars->pipeItr != nullptr) {
        kern_return_t r = ivars->pipeItr->ClearStall(false);
        Log("resetEnablePath: ClearStall ITR -> 0x%x", r);
    }
    if (ivars->pipeRx != nullptr) {
        kern_return_t r = ivars->pipeRx->ClearStall(false);
        Log("resetEnablePath: ClearStall RX -> 0x%x", r);
    }
    if (ivars->pipeTx != nullptr) {
        kern_return_t r = ivars->pipeTx->ClearStall(false);
        Log("resetEnablePath: ClearStall TX -> 0x%x", r);
    }

    ivars->lastLinkUp = false;
    ivars->rxStarted = false;
}

static void
dumpRxBytes(const uint8_t *buf, uint32_t actualByteCount, uint32_t slot, IOReturn status)
{
    if (buf == nullptr || actualByteCount == 0) {
        return;
    }

    auto dumpRange = [buf, slot](uint32_t start, uint32_t end) {
        for (uint32_t i = start; i < end; i += 16) {
            char line[96];
            int n = snprintf(line, sizeof(line), "RXDUMP[%u] %04x:", slot, (unsigned)i);
            for (uint32_t j = 0; j < 16 && i + j < end && n > 0 && n < (int)sizeof(line); j++) {
                n += snprintf(line + n, sizeof(line) - (size_t)n, " %02x", buf[i + j]);
            }
            Log("%s", line);
        }
    };

    Log("RXDUMP slot=%u status=0x%x bytes=%u", slot, status, actualByteCount);

    if (actualByteCount <= 512) {
        dumpRange(0, actualByteCount);
        return;
    }

    dumpRange(0, 64);
    Log("RXDUMP[%u] ...", slot);
    dumpRange(actualByteCount - 64, actualByteCount);
}

static bool
parseRxLayoutCandidate(const uint8_t *buf, uint32_t actualByteCount, uint32_t headerOffset,
                       uint32_t packetBaseOffset, RxParseInfo *info)
{
    if (buf == nullptr || info == nullptr || actualByteCount < headerOffset + sizeof(uint32_t)) {
        return false;
    }

    uint32_t header    = *(const uint32_t *)(buf + headerOffset);
    uint32_t pktCount  = header & 0x1FFF;
    uint32_t descOff   = (header & 0xFFFFE000) >> 13;
    uint32_t descBytes = pktCount * 8;

    if (pktCount == 0 || descOff < packetBaseOffset || descOff + descBytes > actualByteCount) {
        return false;
    }

    if (headerOffset != 0 && descOff + descBytes > headerOffset) {
        return false;
    }

    uint32_t pktOffset = packetBaseOffset;
    for (uint32_t i = 0; i < pktCount; i++) {
        uint64_t pd      = *(const uint64_t *)(buf + descOff + i * 8);
        uint32_t pktLen  = (uint32_t)((pd & 0x7FFF0000) >> 16);

        if (pktLen == 0) {
            return false;
        }
        if (pktOffset + pktLen > descOff) {
            return false;
        }
        pktOffset += pktLen;
    }

    info->headerOffset     = headerOffset;
    info->packetBaseOffset = packetBaseOffset;
    info->descriptorOffset = descOff;
    info->packetCount      = pktCount;
    return true;
}

static bool
parseRxLayout(const uint8_t *buf, uint32_t actualByteCount, RxParseInfo *info)
{
    if (parseRxLayoutCandidate(buf, actualByteCount, 0, 4, info)) {
        return true;
    }
    if (actualByteCount >= 8 && parseRxLayoutCandidate(buf, actualByteCount, actualByteCount - 8, 0, info)) {
        return true;
    }
    if (actualByteCount >= 4 && parseRxLayoutCandidate(buf, actualByteCount, actualByteCount - 4, 0, info)) {
        return true;
    }
    return false;
}

static void
hwDisable(IOUSBHostInterface *iface)
{
    kern_return_t r;
    uint32_t phyFlags;
    uint16_t w;
    uint8_t  b;

    w = 0x0000;
    r = aqWrite(iface, 0x000B, &w, 2);
    Log("hwDisable: RX_CTL=0x0000 -> 0x%x", r);

    w = 0;
    r = aqRead(iface, 0x0022, &w, 2);
    Log("hwDisable: read MEDIUM_STATUS_MODE -> 0x%x val=0x%04x", r, w);
    w &= ~(uint16_t)0x0100;
    r = aqWrite(iface, 0x0022, &w, 2);
    Log("hwDisable: MEDIUM_STATUS_MODE=0x%04x (clear RECEIVE_EN) -> 0x%x", w, r);

    b = 0x00;
    r = aqWrite(iface, 0x00B7, &b, 1);
    Log("hwDisable: ETH_MAC_PATH=0x00 -> 0x%x", r);

    b = 0x00;
    r = aqWrite(iface, 0x00B9, &b, 1);
    Log("hwDisable: BULK_OUT_CTRL=0x00 -> 0x%x", r);

    b = 0x00;
    r = aqWrite(iface, 0x0043, &b, 1);
    Log("hwDisable: BMRX_DMA=0x00 -> 0x%x", r);

    phyFlags = 0;
    r = aqVendorOut(iface, 0x61, &phyFlags, sizeof(phyFlags));
    Log("hwDisable: AQ_PHY_OPS withdraw advertise flags=0x%08x -> 0x%x", phyFlags, r);

    phyFlags = (1u << 18) | (1u << 19);
    r = aqVendorOut(iface, 0x61, &phyFlags, sizeof(phyFlags));
    Log("hwDisable: AQ_PHY_OPS lowPower flags=0x%08x -> 0x%x", phyFlags, r);
}

// --- OSAction dispatch diagnostic ---

void
IMPL(AQC111NIC, OnTimerFired)
{
    Log("OnTimerFired: OSAction dispatch CONFIRMED WORKING (time=%llu)", time);
}

// --- RX path ---

void
IMPL(AQC111NIC, OnRxComplete)
{
    uint32_t slot = *(uint32_t *)action->GetReference();
    Log("OnRxComplete: slot=%u status=0x%x bytes=%u", slot, status, actualByteCount);

    if (status == kIOReturnAborted) {
        return;  // Stop in progress — don't repost
    }
    if (!ivars->interfaceEnabled || !ivars->ioArmed) {
        Log("RX[%u] disabled path — not reposting", slot);
        return;
    }
    if (status == kUSBHostReturnPipeStalled) {
        kern_return_t r = ivars->pipeRx->ClearStall(false);
        Log("RX[%u] stall ClearStall -> 0x%x", slot, r);
        r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        Log("RX[%u] stall repost -> 0x%x", slot, r);
        return;
    }
    if (status != kIOReturnSuccess) {
        // Terminal (device removed, not ready, etc.) — do NOT repost.
        Log("RX[%u] terminal error: status=0x%x — not reposting", slot, status);
        return;
    }
    if (actualByteCount < 4) {
        kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        Log("RX[%u] short buffer repost -> 0x%x", slot, r);
        return;
    }

    // Parse aggregated RX buffer. Hardware revisions / reverse-engineering notes disagree on
    // whether the 4-byte aggregation header is at offset 0 or in the final 8 bytes, so accept
    // whichever layout validates cleanly against the completed transfer length.
    IOAddressSegment range;
    ivars->rxBufs[slot]->GetAddressRange(&range);
    const uint8_t *buf = (const uint8_t *)range.address;
    RxParseInfo layout = {};

    bool shouldDump = false;
    if (actualByteCount == 80 && !ivars->dumpedRx80) {
        ivars->dumpedRx80 = true;
        shouldDump = true;
    } else if (actualByteCount == 432 && !ivars->dumpedRx432) {
        ivars->dumpedRx432 = true;
        shouldDump = true;
    } else if (!ivars->dumpedRxOther) {
        ivars->dumpedRxOther = true;
        shouldDump = true;
    }
    if (shouldDump) {
        dumpRxBytes(buf, actualByteCount, slot, status);
    }

    if (!parseRxLayout(buf, actualByteCount, &layout)) {
        kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
        Log("RX[%u] bad header repost -> 0x%x", slot, r);
        return;
    }

    Log("RX[%u] parsed layout: hdr=%u pkt_base=%u desc=%u count=%u",
        slot, layout.headerOffset, layout.packetBaseOffset, layout.descriptorOffset, layout.packetCount);

    uint32_t pkt_offset = layout.packetBaseOffset;
    uint32_t delivered  = 0;

    for (uint32_t i = 0; i < layout.packetCount; i++) {
        uint64_t pd      = *(const uint64_t *)(buf + layout.descriptorOffset + i * 8);
        bool     drop    = (pd >> 31) & 1;
        bool     ok      = (pd >> 11) & 1;
        uint32_t pkt_len = (uint32_t)((pd & 0x7FFF0000) >> 16);

        if (!drop && ok && pkt_len > 2) {
            uint32_t frame_len = pkt_len - 2;

            if (frame_len < 14) {
                Log("RX[%u] frame[%u] too short for Ethernet: pkt_len=%u frame_len=%u",
                    slot, i, pkt_len, frame_len);
                pkt_offset += pkt_len;
                continue;
            }

            const uint8_t *frame = buf + pkt_offset + 2;
            uint16_t etherType = ((uint16_t)frame[12] << 8) | frame[13];
            Log("RX[%u] frame[%u]: pkt_len=%u frame_len=%u dst=%02x:%02x:%02x:%02x:%02x:%02x src=%02x:%02x:%02x:%02x:%02x:%02x type=0x%04x",
                slot, i, pkt_len, frame_len,
                frame[0], frame[1], frame[2], frame[3], frame[4], frame[5],
                frame[6], frame[7], frame[8], frame[9], frame[10], frame[11],
                etherType);
            if (frame_len >= 32) {
                Log("RX[%u] frame[%u] first32: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                    slot, i,
                    frame[0], frame[1], frame[2], frame[3], frame[4], frame[5], frame[6], frame[7],
                    frame[8], frame[9], frame[10], frame[11], frame[12], frame[13], frame[14], frame[15],
                    frame[16], frame[17], frame[18], frame[19], frame[20], frame[21], frame[22], frame[23],
                    frame[24], frame[25], frame[26], frame[27], frame[28], frame[29], frame[30], frame[31]);
            } else {
                Log("RX[%u] frame[%u] first32 unavailable: frame_len=%u", slot, i, frame_len);
            }

            IOUserNetworkPacket *pkt = nullptr;
            IOReturn allocRet = ivars->pool->allocatePacket(&pkt);
            if (allocRet == kIOReturnSuccess && pkt != nullptr) {
                uint8_t *dst = (uint8_t *)pkt->getDataVirtualAddress();
                memcpy(dst, frame, frame_len);

                IOReturn prepRet = pkt->prepareWithQueue(ivars->rxcQueue, kIOUserNetworkPacketDirectionRx);
                IOReturn offRet = pkt->setDataOffsetAndLength(0, frame_len);
                IOReturn lhlRet = pkt->setLinkHeaderLength(14);
                pkt->setCompletionStatus(kIOReturnSuccess);
                IOUserNetworkPacket *packetArray[1] = { pkt };
                IOReturn enqRet = ivars->rxcQueue->enqueuePackets(packetArray, 1);
                Log("RX[%u] frame[%u] packet metadata: prepare=0x%x offLen=0x%x linkHdr=0x%x enqueuePackets=0x%x",
                    slot, i, prepRet, offRet, lhlRet, enqRet);

                if (enqRet == kIOReturnSuccess) {
                    delivered++;
                } else {
                    IOReturn deallocRet = ivars->pool->deallocatePacket(pkt);
                    Log("RX[%u] frame[%u] deallocate after enqueue failure -> 0x%x",
                        slot, i, deallocRet);
                }
            } else {
                Log("RX[%u] frame[%u] allocatePacket failed -> 0x%x pkt=%p",
                    slot, i, allocRet, pkt);
            }
        }

        pkt_offset += pkt_len;
    }

    if (delivered > 0) {
        Log("RX[%u] %u bytes → %u/%u frames delivered", slot, actualByteCount, delivered, layout.packetCount);
    }

    kern_return_t r = ivars->pipeRx->AsyncIO(ivars->rxBufs[slot], RX_BUF_SIZE, ivars->rxActions[slot], 0);
    Log("RX[%u] repost -> 0x%x", slot, r);
}

// --- ITR (interrupt IN) path — link status ---
//
// byte[1]: bit7=link-up, bits[6:0]=speed code
//   0x0F=5G, 0x10=2.5G, 0x11=1G, 0x13=100M

void
IMPL(AQC111NIC, OnItrComplete)
{
    Log("OnItrComplete: status=0x%x bytes=%u", status, actualByteCount);

    if (status == kIOReturnAborted) {
        return;
    }
    if (!ivars->interfaceEnabled || !ivars->ioArmed) {
        Log("ITR disabled path — not reposting");
        return;
    }
    if (status == kIOReturnSuccess && actualByteCount >= 2) {
        IOAddressSegment range;
        ivars->itrBuf->GetAddressRange(&range);
        const uint8_t *data = (const uint8_t *)range.address;

        uint8_t byte1     = data[1];
        bool    linkUp    = (byte1 >> 7) & 1;
        uint8_t speedCode = byte1 & 0x7F;

        const uint32_t opts = kIOUserNetworkMediaOptionFullDuplex |
                              kIOUserNetworkMediaOptionFlowControl;
        MediaWord media = kIOUserNetworkMediaEthernetAuto;
        if (linkUp) {
            ivars->lastLinkUp = true;
            ensureRxStarted(ivars, speedCode);
            switch (speedCode) {
                case 0x0F: media = kIOUserNetworkMediaEthernet5000BaseT | opts; break;
                case 0x10: media = kIOUserNetworkMediaEthernet2500BaseT | opts; break;
                case 0x11: media = kIOUserNetworkMediaEthernet1000BaseT | opts; break;
                case 0x13: media = kIOUserNetworkMediaEthernet100BaseTX | opts; break;
                default:   media = kIOUserNetworkMediaEthernet1000BaseT | opts; break;
            }
        } else {
            ivars->lastLinkUp = false;
            ensureRxStopped(ivars);
        }

        LinkStatus ls = linkUp ? kIOUserNetworkLinkStatusActive
                                : kIOUserNetworkLinkStatusInactive;
        Log("ITR: byte1=0x%02x linkUp=%d speed=0x%02x -> reportLinkStatus(0x%x, 0x%x)",
            byte1, (int)linkUp, speedCode, ls, media);
        reportLinkStatus(ls, media);
    } else if (status == kUSBHostReturnPipeStalled) {
        kern_return_t r = ivars->pipeItr->ClearStall(false);
        Log("ITR stall ClearStall -> 0x%x", r);
        r = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
        Log("ITR stall repost -> 0x%x", r);
        return;
    } else if (status != kIOReturnSuccess) {
        Log("ITR terminal error: status=0x%x — not reposting", status);
        return;
    }

    kern_return_t r = ivars->pipeItr->AsyncIO(ivars->itrBuf, 16, ivars->itrAction, 0);
    Log("ITR repost -> 0x%x", r);
}

// --- LOCAL overrides ---

kern_return_t
IMPL(AQC111NIC, SetMTU)
{
    Log("SetMTU: %u", mtu);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, GetMaxTransferUnit)
{
    Log("GetMaxTransferUnit");
    *mtu = 1500;
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetHardwareAssists)
{
    Log("SetHardwareAssists: 0x%x", hardwareAssists);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, GetHardwareAssists)
{
    Log("GetHardwareAssists");
    *hardwareAssists = 0;
    return kIOReturnSuccess;
}

// --- Dispatched overrides ---

kern_return_t
IMPL(AQC111NIC, SetInterfaceEnable)
{
    Log("SetInterfaceEnable: %d", isEnable);
    if (isEnable) {
        ivars->interfaceEnabled = true;

        kern_return_t r;
        r = ivars->txsQueue->SetEnable(true); Log("SetInterfaceEnable: txsQueue SetEnable -> 0x%x", r);
        r = ivars->txcQueue->SetEnable(true); Log("SetInterfaceEnable: txcQueue SetEnable -> 0x%x", r);
        r = ivars->rxsQueue->SetEnable(true); Log("SetInterfaceEnable: rxsQueue SetEnable -> 0x%x", r);
        r = ivars->rxcQueue->SetEnable(true); Log("SetInterfaceEnable: rxcQueue SetEnable -> 0x%x", r);

        resetEnablePath(ivars);
        kern_return_t armRet = armAsyncIO(ivars);
        Log("SetInterfaceEnable: armAsyncIO -> 0x%x", armRet);
        hwEnable(ivars->interface, ivars->macAddress);
    } else {
        ivars->interfaceEnabled = false;
        ensureRxStopped(ivars);
        disarmAsyncIO(ivars);
        hwDisable(ivars->interface);

        kern_return_t r;
        r = ivars->rxcQueue->SetEnable(false); Log("SetInterfaceEnable: rxcQueue SetEnable(false) -> 0x%x", r);
        r = ivars->rxsQueue->SetEnable(false); Log("SetInterfaceEnable: rxsQueue SetEnable(false) -> 0x%x", r);
        r = ivars->txcQueue->SetEnable(false); Log("SetInterfaceEnable: txcQueue SetEnable(false) -> 0x%x", r);
        r = ivars->txsQueue->SetEnable(false); Log("SetInterfaceEnable: txsQueue SetEnable(false) -> 0x%x", r);

        ivars->lastLinkUp = false;
        reportLinkStatus(kIOUserNetworkLinkStatusInactive, kIOUserNetworkMediaEthernetAuto);
        Log("SetInterfaceEnable: reportLinkStatus inactive");
    }
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetPromiscuousModeEnable)
{
    Log("SetPromiscuousModeEnable: %d", enable);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetAllMulticastModeEnable)
{
    Log("SetAllMulticastModeEnable: %d", enable);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetMulticastAddresses)
{
    Log("SetMulticastAddresses: count=%u", count);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SelectMediaType)
{
    Log("SelectMediaType: 0x%x", mediaType);
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111NIC, SetWakeOnMagicPacketEnable)
{
    Log("SetWakeOnMagicPacketEnable: %d", enable);
    return kIOReturnSuccess;
}

// --- Media support ---

kern_return_t
AQC111NIC::getSupportedMediaArray(MediaWord *mediaArray, uint32_t *mediaCount)
{
    Log("getSupportedMediaArray");
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
    Log("handleChosenMedia: 0x%x", chosenMedia);
    return kIOReturnSuccess;
}

MediaWord
AQC111NIC::getInitialMedia()
{
    Log("getInitialMedia");
    return kIOUserNetworkMediaEthernetAuto;
}

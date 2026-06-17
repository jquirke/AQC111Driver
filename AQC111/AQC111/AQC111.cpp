//
//  AQC111.cpp
//  AQC111 — Personality A: USB config selector
//
//  Matches IOUSBHostDevice (VID=0x20f4, PID=0xe05a).
//  Opens device, selects Config 1 (vendor-specific, 5Gbps), keeps session
//  open to prevent the USB stack from reverting to Config 2 (CDC).
//  kUSBPreferredConfiguration=2 is set by the device/stack; releasing the
//  session causes immediate reversion to Config 2.
//

#include <os/log.h>

#include <DriverKit/DriverKit.h>
#include <USBDriverKit/USBDriverKit.h>

#include "AQC111.h"

// Log levels — see AQC111NIC.cpp / IMPL_PLAN.md "Log Level Strategy" for the
// full rationale. This personality logs little, but uses the same scheme for
// consistency and so "AQC111LogLevel" works the same way across both.
#define kLogLevelError      0
#define kLogLevelInfo       1
#define kLogLevelDebug      2
#define kLogLevelVerbose    3
static volatile uint8_t gLogLevel = kLogLevelInfo;

#define LogE(fmt, ...) do { if (gLogLevel >= kLogLevelError) os_log(OS_LOG_DEFAULT, "AQC111-A [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__); } while (0)
#define LogI(fmt, ...) do { if (gLogLevel >= kLogLevelInfo)  os_log(OS_LOG_DEFAULT, "AQC111-A [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__); } while (0)

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

struct AQC111_IVars {
    IOUSBHostDevice *device;
};

bool
AQC111::init()
{
    if (!super::init()) return false;
    ivars = IONewZero(AQC111_IVars, 1);
    return ivars != nullptr;
}

void
AQC111::free()
{
    IOSafeDeleteNULL(ivars, AQC111_IVars, 1);
    super::free();
}

kern_return_t
IMPL(AQC111, Start)
{
    kern_return_t ret;

    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        LogE("super Start failed: 0x%x", ret);
        return ret;
    }

    {
        OSDictionary *props = nullptr;
        if (CopyProperties(&props) == kIOReturnSuccess && props != nullptr) {
            applyLogLevelFromDictionary(props);
        }
        OSSafeReleaseNULL(props);
        LogI("Start: gLogLevel=%u (0=Error 1=Info 2=Debug 3=Verbose)", gLogLevel);
    }

    ivars->device = OSDynamicCast(IOUSBHostDevice, provider);
    if (ivars->device == nullptr) {
        LogE("provider is not IOUSBHostDevice");
        return kIOReturnError;
    }

    ret = ivars->device->Open(this, 0, 0);
    if (ret != kIOReturnSuccess) {
        LogE("device Open failed: 0x%x", ret);
        return ret;
    }

    // Select Config 1 and publish interface nubs. Keep session open —
    // releasing it causes kUSBPreferredConfiguration=2 to take effect
    // and the stack reverts to CDC immediately.
    ret = ivars->device->SetConfiguration(1, true);
    if (ret != kIOReturnSuccess) {
        LogE("SetConfiguration(1) failed: 0x%x — aborting, will not RegisterService", ret);
        return ret;
    }
    LogI("SetConfiguration(1) -> success");

    ret = RegisterService();
    LogI("RegisterService -> 0x%x", ret);
    return ret;
}

kern_return_t
IMPL(AQC111, Stop)
{
    LogI("Stop");
    // Close and release the device BEFORE calling SUPERDISPATCH.
    // IOService::Stop_Impl schedules an async cleanup block on the service's
    // auto-created "-Default" queue. If the device is still open when that
    // block fires (force-close path), it races against proxy teardown and
    // dereferences a null field at +0x10 → EXC_BAD_ACCESS.
    // AppleUserECM RE confirms: close providers first, SUPERDISPATCH last.
    if (ivars->device != nullptr) {
        ivars->device->Close(this, 0);
        OSSafeReleaseNULL(ivars->device);
    }
    return Stop(provider, SUPERDISPATCH);
}

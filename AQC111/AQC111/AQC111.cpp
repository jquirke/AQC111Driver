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

#define Log(fmt, ...) os_log(OS_LOG_DEFAULT, "AQC111-A [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__)

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
        Log("super Start failed: 0x%x", ret);
        return ret;
    }

    ivars->device = OSDynamicCast(IOUSBHostDevice, provider);
    if (ivars->device == nullptr) {
        Log("provider is not IOUSBHostDevice");
        return kIOReturnError;
    }

    ret = ivars->device->Open(this, 0, 0);
    if (ret != kIOReturnSuccess) {
        Log("device Open failed: 0x%x", ret);
        return ret;
    }

    // Select Config 1 and publish interface nubs. Keep session open —
    // releasing it causes kUSBPreferredConfiguration=2 to take effect
    // and the stack reverts to CDC immediately.
    ret = ivars->device->SetConfiguration(1, true);
    if (ret != kIOReturnSuccess) {
        Log("SetConfiguration(1) failed: 0x%x — aborting, will not RegisterService", ret);
        return ret;
    }
    Log("SetConfiguration(1) -> success");

    ret = RegisterService();
    Log("RegisterService -> 0x%x", ret);
    return ret;
}

kern_return_t
IMPL(AQC111, Stop)
{
    Log("Stop");
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

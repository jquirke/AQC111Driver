//
//  AQC111.cpp
//  AQC111
//
//  Created by JQ on 3/8/26.
//

#include <os/log.h>

#include <DriverKit/DriverKit.h>
#include <USBDriverKit/USBDriverKit.h>
#include <NetworkingDriverKit/NetworkingDriverKit.h>

#include "AQC111.h"

#define Log(fmt, ...) os_log(OS_LOG_DEFAULT, "AQC111 [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__)

// Endpoint addresses for Config 1 vendor interface (class 255)
#define EP_ITR  0x81   // EP1 IN  Interrupt 16B  — link status
#define EP_RX   0x82   // EP2 IN  Bulk 1024B     — receive
#define EP_TX   0x03   // EP3 OUT Bulk 1024B     — transmit

struct AQC111_IVars {
    IOUSBHostDevice    *device;
    IOUSBHostInterface *interface;
    IOUSBHostPipe      *pipeItr;    // EP1 IN Interrupt
    IOUSBHostPipe      *pipeRx;     // EP2 IN Bulk
    IOUSBHostPipe      *pipeTx;     // EP3 OUT Bulk
};

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

kern_return_t
IMPL(AQC111, Start)
{
    kern_return_t ret;

    // --- Cast provider ---
    ivars->device = OSDynamicCast(IOUSBHostDevice, provider);
    if (ivars->device == nullptr) {
        Log("Start: provider is not IOUSBHostDevice");
        return kIOReturnError;
    }

    // --- Open device ---
    ret = ivars->device->Open(this, 0, 0);
    if (ret != kIOReturnSuccess) {
        Log("Start: device Open failed: 0x%x", ret);
        return ret;
    }

    // --- Select Config 1 (vendor proprietary, prevents CDC match) ---
    ret = ivars->device->SetConfiguration(1, true);
    if (ret != kIOReturnSuccess) {
        Log("Start: SetConfiguration(1) failed: 0x%x", ret);
        ivars->device->Close(this, 0);
        return ret;
    }
    Log("Start: SetConfiguration(1) succeeded");

    // --- Obtain the vendor interface via iterator ---
    uintptr_t iter = 0;
    ret = ivars->device->CreateInterfaceIterator(&iter);
    if (ret != kIOReturnSuccess) {
        Log("Start: CreateInterfaceIterator failed: 0x%x", ret);
        ivars->device->Close(this, 0);
        return ret;
    }

    ret = ivars->device->CopyInterface(iter, &ivars->interface);
    ivars->device->DestroyInterfaceIterator(iter);

    if (ret != kIOReturnSuccess || ivars->interface == nullptr) {
        Log("Start: CopyInterface failed: 0x%x (interface=%p)", ret, ivars->interface);
        ivars->device->Close(this, 0);
        return (ret == kIOReturnSuccess) ? kIOReturnNotFound : ret;
    }
    Log("Start: interface obtained");

    // --- Open interface ---
    ret = ivars->interface->Open(this, 0, nullptr);
    if (ret != kIOReturnSuccess) {
        Log("Start: interface Open failed: 0x%x", ret);
        OSSafeReleaseNULL(ivars->interface);
        ivars->device->Close(this, 0);
        return ret;
    }
    Log("Start: interface opened");

    // --- Claim pipes ---
    ret = ivars->interface->CopyPipe(EP_ITR, &ivars->pipeItr);
    Log("Start: CopyPipe(EP_ITR=0x%02x) -> 0x%x pipe=%p", EP_ITR, ret, ivars->pipeItr);

    ret = ivars->interface->CopyPipe(EP_RX, &ivars->pipeRx);
    Log("Start: CopyPipe(EP_RX =0x%02x) -> 0x%x pipe=%p", EP_RX, ret, ivars->pipeRx);

    ret = ivars->interface->CopyPipe(EP_TX, &ivars->pipeTx);
    Log("Start: CopyPipe(EP_TX =0x%02x) -> 0x%x pipe=%p", EP_TX, ret, ivars->pipeTx);

    if (ivars->pipeItr == nullptr || ivars->pipeRx == nullptr || ivars->pipeTx == nullptr) {
        Log("Start: one or more pipes failed — check endpoint addresses");
        OSSafeReleaseNULL(ivars->pipeItr);
        OSSafeReleaseNULL(ivars->pipeRx);
        OSSafeReleaseNULL(ivars->pipeTx);
        ivars->interface->Close(this, 0);
        OSSafeReleaseNULL(ivars->interface);
        ivars->device->Close(this, 0);
        return kIOReturnNotFound;
    }

    // --- Super start (registers with IOKit) ---
    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        Log("Start: super Start failed: 0x%x", ret);
        OSSafeReleaseNULL(ivars->pipeItr);
        OSSafeReleaseNULL(ivars->pipeRx);
        OSSafeReleaseNULL(ivars->pipeTx);
        ivars->interface->Close(this, 0);
        OSSafeReleaseNULL(ivars->interface);
        ivars->device->Close(this, 0);
        return ret;
    }

    ret = RegisterService();
    if (ret != kIOReturnSuccess) {
        Log("Start: RegisterService failed: 0x%x", ret);
        return ret;
    }

    Log("Start: M1 complete — device open, interface open, all 3 pipes acquired");
    return kIOReturnSuccess;
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------

kern_return_t
IMPL(AQC111, Stop)
{
    Log("Stop");

    OSSafeReleaseNULL(ivars->pipeItr);
    OSSafeReleaseNULL(ivars->pipeRx);
    OSSafeReleaseNULL(ivars->pipeTx);

    if (ivars->interface != nullptr) {
        ivars->interface->Close(this, 0);
        OSSafeReleaseNULL(ivars->interface);
    }

    if (ivars->device != nullptr) {
        kern_return_t closeRet = ivars->device->Close(this, 0);
        Log("Stop: device Close returned 0x%x", closeRet);
    }

    return Stop(provider, SUPERDISPATCH);
}

// ---------------------------------------------------------------------------
// Deprecated pure-virtual stubs — remote dispatch
// ---------------------------------------------------------------------------

kern_return_t
IMPL(AQC111, SetInterfaceEnable)
{
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, SetPromiscuousModeEnable)
{
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, SetMulticastAddresses)
{
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, SetAllMulticastModeEnable)
{
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, SelectMediaType)
{
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, SetWakeOnMagicPacketEnable)
{
    return kIOReturnSuccess;
}

// ---------------------------------------------------------------------------
// Deprecated pure-virtual stubs — LOCAL (direct C++ override, not IPC)
// ---------------------------------------------------------------------------

kern_return_t
AQC111::SetMTU(uint32_t mtu)
{
    return kIOReturnSuccess;
}

kern_return_t
AQC111::GetMaxTransferUnit(uint32_t *mtu)
{
    *mtu = 1500;
    return kIOReturnSuccess;
}

kern_return_t
AQC111::SetHardwareAssists(uint32_t hardwareAssists)
{
    return kIOReturnSuccess;
}

kern_return_t
AQC111::GetHardwareAssists(uint32_t *hardwareAssists)
{
    *hardwareAssists = 0;
    return kIOReturnSuccess;
}

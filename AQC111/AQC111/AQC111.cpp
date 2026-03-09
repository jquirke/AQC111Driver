//
//  AQC111.cpp
//  AQC111
//
//  Created by JQ on 3/8/26.
//

#include <os/log.h>

#include <DriverKit/DriverKit.h>
#include <USBDriverKit/USBDriverKit.h>

#include "AQC111.h"

#define Log(fmt, ...) os_log(OS_LOG_DEFAULT, "AQC111 [" __DATE__ " " __TIME__ "] - " fmt, ##__VA_ARGS__)

kern_return_t
IMPL(AQC111, Start)
{
    kern_return_t ret;

    IOUSBHostDevice* device = OSDynamicCast(IOUSBHostDevice, provider);
    if (device == nullptr) {
        Log("Start: provider is not IOUSBHostDevice");
        return kIOReturnError;
    }

    ret = device->Open(this, 0, 0);
    if (ret != kIOReturnSuccess) {
        Log("Start: device Open failed: 0x%x", ret);
        return ret;
    }

    Log("Start: setting configuration 1");
    ret = device->SetConfiguration(1, true);
    if (ret != kIOReturnSuccess) {
        Log("Start: SetConfiguration(1) failed: 0x%x", ret);
        device->Close(this, 0);
        return ret;
    }
    Log("Start: SetConfiguration(1) succeeded");

    ret = Start(provider, SUPERDISPATCH);
    if (ret != kIOReturnSuccess) {
        Log("Start: super Start failed: 0x%x", ret);
        device->Close(this, 0);
        return ret;
    }

    // Required when inheriting IOService: registers this driver so the OS
    // knows Start succeeded and interface matching can proceed.
    ret = RegisterService();
    if (ret != kIOReturnSuccess) {
        Log("Start: RegisterService failed: 0x%x", ret);
        return ret;
    }

    Log("Start: complete");
    return kIOReturnSuccess;
}

kern_return_t
IMPL(AQC111, Stop)
{
    Log("Stop");

    IOUSBHostDevice* device = OSDynamicCast(IOUSBHostDevice, provider);
    if (device != nullptr) {
        kern_return_t closeRet = device->Close(this, 0);
        Log("Stop: device Close returned 0x%x", closeRet);
    }

    return Stop(provider, SUPERDISPATCH);
}

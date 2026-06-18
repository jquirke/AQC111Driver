//
//  AQC111LogUserClient.cpp
//  AQC111 — diagnostic user client for live log-level control
//

#include <os/log.h>

#include <DriverKit/DriverKit.h>
#include <DriverKit/IOUserClient.h>

#include "AQC111LogUserClient.h"

extern "C" kern_return_t AQC111SetNICLogLevel(uint32_t level);
extern "C" uint32_t AQC111GetNICLogLevel(void);

enum {
    kAQC111LogUserClientSetLogLevel = 0,
};

bool
AQC111LogUserClient::init()
{
    return super::init();
}

void
AQC111LogUserClient::free()
{
    super::free();
}

kern_return_t
IMPL(AQC111LogUserClient, Start)
{
    os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - Start provider=%p", provider);
    return Start(provider, SUPERDISPATCH);
}

kern_return_t
IMPL(AQC111LogUserClient, Stop)
{
    os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - Stop provider=%p", provider);
    return Stop(provider, SUPERDISPATCH);
}

kern_return_t
AQC111LogUserClient::ExternalMethod(uint64_t selector,
                                    IOUserClientMethodArguments *arguments,
                                    const IOUserClientMethodDispatch *dispatch,
                                    OSObject *target,
                                    void *reference)
{
    if (selector != kAQC111LogUserClientSetLogLevel) {
        os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - unsupported selector=%llu", selector);
        return kIOReturnUnsupported;
    }
    if (arguments == nullptr ||
        arguments->scalarInput == nullptr ||
        arguments->scalarInputCount != 1) {
        os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - bad set-log-level arguments");
        return kIOReturnBadArgument;
    }

    uint32_t oldLevel = AQC111GetNICLogLevel();
    uint64_t requestedLevel = arguments->scalarInput[0];
    if (requestedLevel > 3) {
        os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - invalid log level=%llu", requestedLevel);
        return kIOReturnBadArgument;
    }

    kern_return_t ret = AQC111SetNICLogLevel((uint32_t)requestedLevel);
    os_log(OS_LOG_DEFAULT, "AQC111-LogUserClient [" __DATE__ " " __TIME__ "] - set log level %u -> %llu ret=0x%x",
        oldLevel, requestedLevel, ret);
    return ret;
}

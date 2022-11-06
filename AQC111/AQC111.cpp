//
//  AQC111.cpp
//  AQC111
//
//  Created by Jeremy Quirke on 11/6/22.
//

#include <os/log.h>

#include <DriverKit/IOUserServer.h>
#include <DriverKit/IOLib.h>

#include "AQC111.h"

kern_return_t
IMPL(AQC111, Start)
{
    kern_return_t ret;
    ret = Start(provider, SUPERDISPATCH);
    os_log(OS_LOG_DEFAULT, "Hello World");
    return ret;
}

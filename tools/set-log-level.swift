#!/usr/bin/swift
//
//  set-log-level.swift
//  Live log-level control for the running AQC111NIC dext — see
//  IMPL_PLAN.md "Log Level Strategy". Opens the AQC111LogUserClient and
//  calls selector 0 with the requested log level. No restart required.
//
//  Usage: ./set-log-level.swift <0-3>   (0=Error 1=Info 2=Debug 3=Verbose)
//

import IOKit
import Foundation

guard CommandLine.arguments.count == 2, let level = UInt32(CommandLine.arguments[1]), level <= 3 else {
    print("Usage: \(CommandLine.arguments[0]) <0-3>  (0=Error 1=Info 2=Debug 3=Verbose)")
    exit(1)
}

// Open the NIC personality directly. Most logging is emitted from AQC111NIC,
// and DriverKit user-client calls are delivered to the service passed to
// IOServiceOpen(). Opening the AQC111 USB-device personality updates that
// personality's process-local copy, not necessarily the NIC instance.
let matching = IOServiceMatching("IOUserNetworkEthernet") as NSMutableDictionary
matching["IOPropertyMatch"] = ["IOUserClass": "AQC111NIC"]
let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
guard service != 0 else {
    print("AQC111NIC service not found — is the dext loaded and the network interface attached?")
    exit(1)
}
defer { IOObjectRelease(service) }

var connection: io_connect_t = 0
var result = IOServiceOpen(service, mach_task_self_, 0, &connection)
guard result == KERN_SUCCESS else {
    print(String(format: "IOServiceOpen failed: 0x%x", result))
    if result == kIOReturnNotPermitted {
        print("The dext must be signed with com.apple.developer.driverkit.allow-any-userclient-access, or the caller must have userclient-access for au.com.jquirke.AQC111Driver.")
    }
    exit(1)
}
defer { IOServiceClose(connection) }

var input: [UInt64] = [UInt64(level)]
result = input.withUnsafeBufferPointer { buffer in
    IOConnectCallScalarMethod(connection, 0, buffer.baseAddress, 1, nil, nil)
}
guard result == KERN_SUCCESS else {
    print(String(format: "IOConnectCallScalarMethod(set log level) failed: 0x%x", result))
    exit(1)
}

print("Set AQC111LogLevel=\(level). Check `log stream` to confirm.")

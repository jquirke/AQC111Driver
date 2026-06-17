#!/usr/bin/swift
//
//  set-log-level.swift
//  Live log-level control for the running AQC111NIC dext — see
//  IMPL_PLAN.md "Log Level Strategy". Calls IORegistryEntrySetCFProperties
//  against the matched AQC111NIC service, which routes to our
//  SetProperties() override (AQC111NIC.cpp). No restart required.
//
//  Usage: ./set-log-level.swift <0-3>   (0=Error 1=Info 2=Debug 3=Verbose)
//  May require sudo depending on IOKit property-set permissions.
//

import IOKit
import Foundation

guard CommandLine.arguments.count == 2, let level = UInt32(CommandLine.arguments[1]), level <= 3 else {
    print("Usage: \(CommandLine.arguments[0]) <0-3>  (0=Error 1=Info 2=Debug 3=Verbose)")
    exit(1)
}

// IOServiceMatching("AQC111NIC") doesn't work here: DriverKit services are
// published with IOClass=IOUserNetworkEthernet (the generic kernel-side
// proxy), not the actual dext subclass name. "IOUserClass" is the property
// that actually carries "AQC111NIC" (confirmed via `ioreg -r -c AQC111NIC`).
let matching = ["IOUserClass": "AQC111NIC"] as CFDictionary
let service = IOServiceGetMatchingService(kIOMainPortDefault, matching)
guard service != 0 else {
    print("AQC111NIC service not found — is the dext loaded and the interface attached?")
    exit(1)
}
defer { IOObjectRelease(service) }

let props: [String: Any] = ["AQC111LogLevel": level]
let result = IORegistryEntrySetCFProperties(service, props as CFDictionary)
if result == KERN_SUCCESS {
    print("Set AQC111LogLevel=\(level). Check `log stream` to confirm.")
} else {
    print(String(format: "IORegistryEntrySetCFProperties failed: 0x%x (try sudo?)", result))
    exit(1)
}

//
//  ContentView.swift
//  AQC111Driver
//
//  Created by Jeremy Quirke on 11/6/22.
//

import SwiftUI
import SystemExtensions

struct ContentView : View {
    var body: some View {
        VStack {
            Text("USBApp")
            HStack {
                Button(action: ExtensionManager.shared.activate) {
                    Text("Activate")
                }
                Button(action: ExtensionManager.shared.deactivate) {
                    Text("Deactivate")
                }
            }
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
    }
}

struct ContentView_Previews: PreviewProvider {
    static var previews: some View {
        ContentView()
    }
}

import Cocoa
import SystemExtensions
import OSLog

private let logger = Logger(subsystem: "au.com.jquirke.AQC111Loader", category: "main")
private let dextID = "au.com.jquirke.AQC111Driver"

@main
final class AppDelegate: NSObject, NSApplicationDelegate, OSSystemExtensionRequestDelegate {

    static func main() {
        let app = NSApplication.shared
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }

    var window: NSWindow!
    var statusLabel: NSTextField!

    func applicationDidFinishLaunching(_ notification: Notification) {
        window = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 800, height: 600),
            styleMask: [.titled, .closable, .resizable],
            backing: .buffered,
            defer: false
        )
        window.title = "AQC111 Driver Loader"
        window.center()

        let installButton = NSButton(title: "Install", target: self, action: #selector(install))
        installButton.frame = NSRect(x: 20, y: 558, width: 120, height: 32)
        window.contentView?.addSubview(installButton)

        let uninstallButton = NSButton(title: "Uninstall", target: self, action: #selector(uninstall))
        uninstallButton.frame = NSRect(x: 155, y: 558, width: 120, height: 32)
        window.contentView?.addSubview(uninstallButton)

        statusLabel = NSTextField(wrappingLabelWithString: "Ready.")
        statusLabel.frame = NSRect(x: 20, y: 10, width: 760, height: 538)
        statusLabel.isSelectable = true
        statusLabel.font = NSFont.monospacedSystemFont(ofSize: 11, weight: .regular)
        window.contentView?.addSubview(statusLabel)

        window.makeKeyAndOrderFront(nil)
    }

    @objc func install() {
        set(status: "Activating \(dextID)…")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: dextID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        logger.info("Submitted activation request for \(dextID)")
    }

    @objc func uninstall() {
        set(status: "Deactivating \(dextID)…")
        let request = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: dextID,
            queue: .main
        )
        request.delegate = self
        OSSystemExtensionManager.shared.submitRequest(request)
        logger.info("Submitted deactivation request for \(dextID)")
    }

    // MARK: - OSSystemExtensionRequestDelegate

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            set(status: "Done.")
            logger.info("Request completed.")
        case .willCompleteAfterReboot:
            set(status: "Will complete after reboot.")
            logger.info("Request will complete after reboot.")
        @unknown default:
            set(status: "Unknown result: \(result.rawValue)")
        }
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFailWithError error: Error) {
        set(status: "Failed: \(error.localizedDescription)")
        logger.error("Request failed: \(error)")
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        set(status: "Approve in System Settings → Privacy & Security.")
        logger.info("Needs user approval.")
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        logger.info("Replacing \(existing.bundleVersion) with \(ext.bundleVersion)")
        return .replace
    }

    // MARK: -

    private func set(status: String) {
        statusLabel.stringValue = status
    }
}

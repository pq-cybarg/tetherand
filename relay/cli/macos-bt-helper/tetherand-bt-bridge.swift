// tetherand-bt-bridge.swift
//
// Tiny macOS helper that connects to a paired Android device over
// RFCOMM (using IOBluetooth) and bridges the channel to stdin / stdout
// for the Rust CLI to consume. Spawned by `tetherand run --transport bt`.
//
// Stdin bytes → RFCOMM write toward the Seeker.
// RFCOMM read from the Seeker → stdout bytes.
//
// Process exit codes:
//   0  clean disconnect (channel closed by either side)
//   1  device not found / not paired
//   2  SDP query found no Tetherand UUID
//   3  RFCOMM open failed
//   4  argument parse / usage error
//
// Build with:
//   swiftc -O -o tetherand-bt-bridge tetherand-bt-bridge.swift \
//          -framework IOBluetooth -framework Foundation
//
// The Tetherand-private service UUID matches the one in
// relay/transport-bt/src/lib.rs:
//   7e7ae72d-0000-1000-8000-00805F9B34FB
//
// Usage:
//   tetherand-bt-bridge --device <Seeker-name-or-address>
//   tetherand-bt-bridge --list

import Foundation
import IOBluetooth

let TETHERAND_UUID_STRING = "7e7ae72d-0000-1000-8000-00805f9b34fb"

// IOBluetoothSDPUUID requires a 128-bit byte representation. We
// build it from the UUID string by hand because IOBluetoothSDPUUID
// has no convenient string initialiser.
func tetherandSdpUuid() -> IOBluetoothSDPUUID {
    var bytes = [UInt8](repeating: 0, count: 16)
    let hex = TETHERAND_UUID_STRING.replacingOccurrences(of: "-", with: "")
    for i in 0..<16 {
        let start = hex.index(hex.startIndex, offsetBy: i * 2)
        let end   = hex.index(start, offsetBy: 2)
        bytes[i] = UInt8(hex[start..<end], radix: 16) ?? 0
    }
    return IOBluetoothSDPUUID(bytes: &bytes, length: 16)
}

// MARK: - RFCOMM channel delegate

final class ChannelBridge: NSObject, IOBluetoothRFCOMMChannelDelegate {
    private let stdoutHandle = FileHandle.standardOutput
    private var stderrHandle = FileHandle.standardError
    private var channel: IOBluetoothRFCOMMChannel?
    private let stdinQueue = DispatchQueue(label: "bt-bridge.stdin", qos: .userInitiated)

    func attach(_ ch: IOBluetoothRFCOMMChannel) {
        self.channel = ch
        ch.setDelegate(self)
        // Spawn a background reader that feeds stdin → RFCOMM.
        stdinQueue.async { [weak self] in
            self?.pumpStdin()
        }
    }

    private func pumpStdin() {
        let inHandle = FileHandle.standardInput
        // Max RFCOMM MTU on macOS is typically 1009 bytes per channel
        // write. We chunk stdin into reads up to that size — chunks
        // arrive in-order on the Android side because RFCOMM is a
        // stream over an L2CAP connection.
        let mtu = Int(channel?.getMTU() ?? 1009)
        while true {
            let chunk: Data
            do {
                guard let data = try inHandle.read(upToCount: mtu) else { break }
                if data.isEmpty { break }
                chunk = data
            } catch {
                break
            }
            var bytes = [UInt8](chunk)
            let rc = bytes.withUnsafeMutableBufferPointer { buf -> IOReturn in
                guard let base = buf.baseAddress else { return kIOReturnError }
                return channel?.writeSync(base, length: UInt16(buf.count)) ?? kIOReturnNotOpen
            }
            if rc != kIOReturnSuccess {
                stderrHandle.write("rfcomm write failed: \(rc)\n".data(using: .utf8)!)
                break
            }
        }
        channel?.close()
    }

    // MARK: IOBluetoothRFCOMMChannelDelegate

    func rfcommChannelData(_ rfcommChannel: IOBluetoothRFCOMMChannel!,
                           data dataPointer: UnsafeMutableRawPointer!,
                           length dataLength: Int) {
        let buf = Data(bytes: dataPointer, count: dataLength)
        stdoutHandle.write(buf)
    }

    func rfcommChannelClosed(_ rfcommChannel: IOBluetoothRFCOMMChannel!) {
        // Either side closed; let the run loop exit so the process can wind down.
        CFRunLoopStop(CFRunLoopGetMain())
    }

    func rfcommChannelOpenComplete(_ rfcommChannel: IOBluetoothRFCOMMChannel!, status error: IOReturn) {
        if error != kIOReturnSuccess {
            stderrHandle.write("rfcomm open failed: \(error)\n".data(using: .utf8)!)
            exit(3)
        }
    }

    // The remaining delegate methods we don't act on. Stub them so the
    // runtime never sends a "responds to selector" probe followed by
    // a crash; the delegate protocol is informal NSObject-style.
    func rfcommChannelWriteComplete(_ rfcommChannel: IOBluetoothRFCOMMChannel!,
                                    refcon: UnsafeMutableRawPointer!,
                                    status error: IOReturn) {}
    func rfcommChannelFlowControlChanged(_ rfcommChannel: IOBluetoothRFCOMMChannel!) {}
    func rfcommChannelControlSignalsChanged(_ rfcommChannel: IOBluetoothRFCOMMChannel!) {}
    func rfcommChannelQueueSpaceAvailable(_ rfcommChannel: IOBluetoothRFCOMMChannel!) {}
}

// MARK: - Discovery

func listPairedDevices() {
    guard let devices = IOBluetoothDevice.pairedDevices() as? [IOBluetoothDevice] else {
        print("(no paired devices)")
        return
    }
    for d in devices {
        let name = d.name ?? "(unnamed)"
        let addr = d.addressString ?? "??:??:??:??:??:??"
        print("\(addr)\t\(name)")
    }
}

func findDevice(byNameOrAddress target: String) -> IOBluetoothDevice? {
    guard let devices = IOBluetoothDevice.pairedDevices() as? [IOBluetoothDevice] else {
        return nil
    }
    // Try exact address match first; fall back to case-insensitive
    // name contains-match so users can type the model name.
    if let m = devices.first(where: { ($0.addressString ?? "").caseInsensitiveCompare(target) == .orderedSame }) {
        return m
    }
    return devices.first(where: { ($0.name ?? "").lowercased().contains(target.lowercased()) })
}

// Probe SDP for the Tetherand UUID, return the RFCOMM channel ID or nil.
func resolveRfcommChannel(on device: IOBluetoothDevice) -> UInt8? {
    // performSDPQuery is synchronous when called as `performSDPQuery(nil)`
    // (deprecated form) — the modern form posts to a delegate. We use
    // the synchronous form because we run inside a dedicated run loop
    // and the helper has nothing else to do meanwhile.
    let queryResult = device.performSDPQuery(nil)
    if queryResult != kIOReturnSuccess {
        FileHandle.standardError.write("sdp query failed: \(queryResult)\n".data(using: .utf8)!)
        return nil
    }
    let uuid = tetherandSdpUuid()
    guard let record = device.getServiceRecord(for: uuid) else {
        return nil
    }
    var ch: UInt8 = 0
    if record.getRFCOMMChannelID(&ch) == kIOReturnSuccess {
        return ch
    }
    return nil
}

// MARK: - Main

func usage() -> Never {
    FileHandle.standardError.write("""
    tetherand-bt-bridge — IOBluetooth RFCOMM bridge for tetherand CLI

    USAGE:
        tetherand-bt-bridge --device <name-or-address>
        tetherand-bt-bridge --list

    """.data(using: .utf8)!)
    exit(4)
}

let args = CommandLine.arguments
if args.count == 2 && args[1] == "--list" {
    listPairedDevices()
    exit(0)
}
guard args.count == 3, args[1] == "--device" else { usage() }
let target = args[2]

guard let device = findDevice(byNameOrAddress: target) else {
    FileHandle.standardError.write("no paired device matches '\(target)'\n".data(using: .utf8)!)
    exit(1)
}

guard let channelId = resolveRfcommChannel(on: device) else {
    FileHandle.standardError.write("paired device '\(target)' has no Tetherand SDP record\n".data(using: .utf8)!)
    exit(2)
}

let bridge = ChannelBridge()
var rfcomm: IOBluetoothRFCOMMChannel? = nil
let openResult = device.openRFCOMMChannelAsync(&rfcomm, withChannelID: channelId, delegate: bridge)
if openResult != kIOReturnSuccess || rfcomm == nil {
    FileHandle.standardError.write("rfcomm open returned \(openResult)\n".data(using: .utf8)!)
    exit(3)
}

bridge.attach(rfcomm!)

// Run the IOBluetooth run loop until the channel closes
// (rfcommChannelClosed calls CFRunLoopStop).
CFRunLoopRun()
exit(0)

import BufoContract
import BufoKit
import Foundation
import os

// The JSON CLI (PLAN.md, The JSON CLI): one JSON object on stdout per run,
// `{"error": …}` and a nonzero exit on failure. No output type carries a
// placement. `daemon` runs only as launchd starts it.

func emit<T: Encodable>(_ value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    let data = (try? encoder.encode(value)) ?? Data(#"{"error":"output didn't encode"}"#.utf8)
    FileHandle.standardOutput.write(data + Data("\n".utf8))
}

func fail(_ message: String, code: Int32 = 1) -> Never {
    emit(["error": message])
    exit(code)
}

func attempt<T>(_ body: () throws -> T) -> T {
    do { return try body() } catch { fail("\(error)") }
}

let usage = """
    usage: bufo status
           sudo bufo install --binary <path> --state <directory> --label <label> --service <name>
           sudo <installed bufo> update <artifact>
           sudo <installed bufo> uninstall
           sudo <installed bufo> arm <account> <public key file>
           sudo <installed bufo> retire <account>
           sudo <installed bufo> listen <tailnet address> <port>
           sudo <installed bufo> peer add <tailnet address> [--port <port>] [--may-plant] [--code]
           sudo <installed bufo> peer remove <tailnet address>
           sudo <installed bufo> plant ssh-key --bait <[user@]host> --detector <tailnet address>
           sudo <installed bufo> rotate <[user@]host>
           sudo <installed bufo> unplant <[user@]host>
           sudo <installed bufo> resume
           sudo <installed bufo> host add <name> --requirement <code requirement> --user <account>
           sudo <installed bufo> host remove <name>
    """
let executable = URL(fileURLWithPath: Bundle.main.executablePath ?? CommandLine.arguments[0]).resolvingSymlinksInPath()
let arguments = Array(CommandLine.arguments.dropFirst())

func options(_ names: [String]) -> [String: String] {
    var values: [String: String] = [:]
    var rest = arguments.dropFirst()
    while let flag = rest.popFirst() {
        guard flag.hasPrefix("--"), names.contains(String(flag.dropFirst(2))), let value = rest.popFirst() else { fail(usage, code: 2) }
        values[String(flag.dropFirst(2))] = value
    }
    guard values.count == names.count else { fail(usage, code: 2) }
    return values
}

func installed() -> InstallConfig {
    switch InstallConfig.find(beside: executable) {
    case .installed(let config): return config
    case .notInstalled: fail("this binary isn't an installed one; run the installed binary")
    case .refused(let why): fail(why)
    }
}

/// Asks the daemon, as root here, for a change.
func change(_ request: [String: String], timeout: TimeInterval = 60) -> Data {
    guard geteuid() == 0 else { fail("this takes root at the watcher: run it with sudo") }
    let config = installed()
    return attempt { try Service.call(config.service, requirement: try Signature.ofSelf().requirement, request, timeout: timeout) }
}

/// Plants, rotates, or takes off a decoy (PLAN.md, Placing bait): the
/// daemon runs the operation and hands back scripts, which run on the bait
/// laptop as the owner who ran sudo, over their own SSH access, with the
/// laptop's pinned host key and no ssh config. Nothing printed names the decoy.
func plant(_ first: [String: String]) -> Never {
    guard geteuid() == 0 else { fail("this takes root at the watcher: run it with sudo") }
    guard let owner = ProcessInfo.processInfo.environment["SUDO_USER"], owner != "root", getpwnam(owner) != nil else {
        fail("run it with sudo from the account that reaches the bait laptop over SSH")
    }
    var request = first.merging(["request": "plant"]) { $1 }
    while true {
        let reply = attempt { try JSONDecoder().decode([String: String].self, from: change(request, timeout: 150)) }
        if let fingerprint = reply["confirm"] {
            let prompt = "The bait laptop's SSH host key is \(fingerprint).\nCheck it there (ssh-keygen -lf on its host key) and type yes if it matches: "
            FileHandle.standardError.write(Data(prompt.utf8))
            guard let tty = FileHandle(forReadingAtPath: "/dev/tty"),
                  String(decoding: tty.availableData, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines) == "yes" else {
                fail("the bait laptop's host key wasn't confirmed")
            }
            request["confirm"] = fingerprint
        } else if let script = reply["run"], let destination = reply["destination"], let hostKey = reply["hostKey"] {
            let (output, status) = attempt { try runOnBait(script, destination: destination, hostKey: hostKey, as: owner) }
            request = ["request": "plant", "start": "resume", "output": output.base64EncodedString(), "status": "\(status)"]
        } else if let done = reply["done"] {
            emit(["done": done])
            exit(0)
        } else {
            fail("the daemon's answer didn't read")
        }
    }
}

/// Runs `script` with `/bin/sh` on the bait laptop as `owner`, through
/// `/usr/bin/ssh` with no config and only the pinned host key; returns its
/// output, up to 4 MB, and exit status.
func runOnBait(_ script: String, destination: String, hostKey: String, as owner: String) throws -> (Data, Int32) {
    let host = String(destination.split(separator: "@").last ?? "")
    var template = Array("/private/tmp/.XXXXXXXX".utf8CString)
    guard let directory = mkdtemp(&template).map({ String(cString: $0) }) else { throw Refusal("no temporary directory") }
    defer { try? FileManager.default.removeItem(atPath: directory) }
    let known = directory + "/known"
    guard chmod(directory, 0o755) == 0,
          FileManager.default.createFile(atPath: known, contents: Data("\(host) \(hostKey)\n".utf8), attributes: [.posixPermissions: 0o644]) else {
        throw Refusal("the pinned host key couldn't be set out")
    }
    var environment = ["/usr/bin/env"]
    if let agent = ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] { environment.append("SSH_AUTH_SOCK=" + agent) }
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/usr/bin/sudo")
    process.arguments = ["-u", owner, "-H"] + environment + [
        "/usr/bin/ssh", "-F", "/dev/null", "-T", "-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null",
        "-o", "StrictHostKeyChecking=yes", "-o", "CheckHostIP=no", "-o", "UpdateHostKeys=no", "-o", "ControlPath=none",
        "-o", "ForwardAgent=no", "-o", "ForwardX11=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectTimeout=10",
        "-o", "ServerAliveInterval=10", "-o", "LogLevel=ERROR", "--", destination, "/bin/sh -s",
    ]
    let input = Pipe(), output = Pipe()
    process.standardInput = input
    process.standardOutput = output
    try process.run()
    let collected = Collected()
    let reading = DispatchSemaphore(value: 0)
    DispatchQueue.global().async {
        while collected.data.count <= 4 * 1024 * 1024 {
            let chunk = output.fileHandleForReading.availableData
            if chunk.isEmpty { break }
            collected.data += chunk
        }
        reading.signal()
    }
    try input.fileHandleForWriting.write(contentsOf: Data(script.utf8))
    try input.fileHandleForWriting.close()
    reading.wait()
    process.waitUntilExit()
    return (collected.data, process.terminationStatus)
}

final class Collected: @unchecked Sendable {
    var data = Data()
}

/// A pairing code typed at this watcher, never echoed or taken from the command line.
func readCode() -> String {
    if isatty(0) != 0 {
        var buffer = [CChar](repeating: 0, count: 256)
        guard readpassphrase("pairing code from the other watcher: ", &buffer, buffer.count, RPP_REQUIRE_TTY) != nil else {
            fail("no pairing code")
        }
        return String(decoding: buffer.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }
    return readLine() ?? ""
}

struct Removed: Encodable {
    var removed: [String]
    var decoysRetired: Int
}

switch arguments.first {
case "status":
    switch InstallConfig.find(beside: executable) {
    case .notInstalled: emit(Status.notInstalled)
    case .refused(let why): fail(why)
    case .installed(let config):
        emit(attempt { try Service.status(config.service, requirement: try Signature.ofSelf().requirement) })
    }
case "install":
    let values = options(["binary", "state", "label", "service"])
    let config = attempt {
        try Installer.install(artifact: executable.path, binary: values["binary"]!, label: values["label"]!,
                              service: values["service"]!, state: values["state"]!)
    }
    emit(["installed": config.label])
case "update" where arguments.count == 2:
    let config = installed()
    let new = attempt { try Installer.update(artifact: arguments[1], binary: executable.path, config: config) }
    emit(["updated": new.version])
case "uninstall" where arguments.count == 1:
    let config = installed()
    let removed = attempt { try Installer.uninstall(binary: executable.path, config: config) }
    emit(Removed(removed: removed.files, decoysRetired: removed.decoys))
case "arm" where arguments.count == 3, "retire" where arguments.count == 2:
    var request = ["request": arguments[0], "account": arguments[1]]
    if arguments[0] == "arm" {
        guard let line = try? String(contentsOfFile: arguments[2], encoding: .utf8), line.utf8.count < 16 * 1024 else {
            fail("the public key file doesn't read")
        }
        request["key"] = line.trimmingCharacters(in: .whitespacesAndNewlines)
    }
    _ = change(request)
    emit([arguments[0] == "arm" ? "armed" : "retired": true])
case "listen" where arguments.count == 3:
    _ = change(["request": "listen", "address": arguments[1], "port": arguments[2]])
    emit(["listening": "\(arguments[1]) port \(arguments[2])"])
case "peer" where arguments.count >= 3 && arguments[1] == "add":
    var request = ["request": "peer-add", "address": arguments[2], "may-plant": "no"]
    var rest = arguments.dropFirst(3)
    while let flag = rest.popFirst() {
        switch flag {
        case "--port":
            guard let port = rest.popFirst() else { fail(usage, code: 2) }
            request["port"] = port
        case "--may-plant": request["may-plant"] = "yes"
        case "--code": request["code"] = readCode()
        default: fail(usage, code: 2)
        }
    }
    let reply = change(request)
    // The code is shown once, here, for the owner to type at the other watcher.
    if let code = (try? JSONDecoder().decode([String: String].self, from: reply))?["code"] {
        emit(["pinned": arguments[2], "code": code])
    } else {
        emit(["pinned": arguments[2]])
    }
case "peer" where arguments.count == 3 && arguments[1] == "remove":
    _ = change(["request": "peer-remove", "address": arguments[2]])
    emit(["unpinned": arguments[2]])
case "plant" where arguments.count == 6 && arguments[1] == "ssh-key":
    var values: [String: String] = [:]
    for index in stride(from: 2, to: 6, by: 2) where ["--bait", "--detector"].contains(arguments[index]) {
        values[String(arguments[index].dropFirst(2))] = arguments[index + 1]
    }
    guard let bait = values["bait"], let detector = values["detector"] else { fail(usage, code: 2) }
    plant(["start": "plant", "destination": bait, "detector": detector])
case "rotate" where arguments.count == 2, "unplant" where arguments.count == 2:
    plant(["start": arguments[0], "destination": arguments[1]])
case "resume" where arguments.count == 1:
    plant(["start": "resume"])
case "host" where arguments.count == 7 && arguments[1] == "add":
    var values: [String: String] = [:]
    for index in stride(from: 3, to: 7, by: 2) where ["--requirement", "--user"].contains(arguments[index]) {
        values[String(arguments[index].dropFirst(2))] = arguments[index + 1]
    }
    guard let requirement = values["requirement"], let user = values["user"] else { fail(usage, code: 2) }
    _ = change(["request": "host-add", "name": arguments[2], "requirement": requirement, "user": user])
    emit(["pinned": arguments[2]])
case "host" where arguments.count == 3 && arguments[1] == "remove":
    _ = change(["request": "host-remove", "name": arguments[2]])
    emit(["unpinned": arguments[2]])
case "daemon" where arguments.count == 1:
    guard geteuid() == 0, getppid() == 1 else { fail("the daemon runs only as launchd starts it") }
    let config = installed()
    let log = Logger(subsystem: config.label, category: "daemon")
    let me = attempt { try Signature.ofSelf() }
    let watcher = attempt { () throws -> Watcher in
        let text = try String(contentsOfFile: config.state + "/watcher", encoding: .utf8)
        guard let watcher = UUID(uuidString: text.trimmingCharacters(in: .whitespacesAndNewlines)) else { throw Refusal("no watcher id") }
        return try Watcher(state: config.state, word: String(config.label.split(separator: ".").last ?? ""), watcher: watcher,
                            version: me.version, log: log)
    }
    signal(SIGTERM, SIG_IGN)
    let terminate = DispatchSource.makeSignalSource(signal: SIGTERM, queue: .main)
    terminate.setEventHandler {
        watcher.stop()
        exit(0)
    }
    terminate.resume()
    watcher.start()
    log.notice("started, version \(me.version, privacy: .public)")
    Service.serve(config.service, requirement: me.requirement, hosts: { watcher.hostIdentities }) { request, caller in
        guard case .bufo(let root) = caller else {
            guard case .host(let id) = caller else { throw Refusal("refused") }
            return try watcher.host(id, request)
        }
        switch request["request"] {
        case "status":
            return try JSONEncoder().encode(watcher.status())
        case "arm", "retire":
            guard root else { throw Refusal("this takes root at the watcher") }
            guard let account = request["account"] else { throw Refusal("no account") }
            if request["request"] == "arm" {
                try watcher.arm(account: account, keyLine: request["key"] ?? "")
            } else {
                try watcher.retire(account: account)
            }
            return Data("{}".utf8)
        case "host-add", "host-remove":
            guard root else { throw Refusal("this takes root at the watcher") }
            if request["request"] == "host-add" {
                try watcher.addHost(name: request["name"] ?? "", requirement: request["requirement"] ?? "", user: request["user"] ?? "")
            } else {
                try watcher.removeHost(name: request["name"] ?? "")
            }
            return Data("{}".utf8)
        case "plant":
            guard root else { throw Refusal("this takes root at the watcher") }
            return try JSONEncoder().encode(watcher.planting(request))
        case "listen", "peer-add", "peer-remove":
            guard root else { throw Refusal("this takes root at the watcher") }
            let address = request["address"] ?? ""
            func port(_ text: String?) throws -> UInt16? {
                guard let text else { return nil }
                guard let port = UInt16(text), port > 0 else { throw Refusal("that isn't a port") }
                return port
            }
            switch request["request"] {
            case "listen":
                try watcher.listen(address: address, port: try port(request["port"]) ?? 0)
            case "peer-add":
                let code = try watcher.addPeer(address: address, port: try port(request["port"]),
                                                mayPlant: request["may-plant"] == "yes", code: request["code"])
                return try JSONEncoder().encode(code.map { ["code": $0] } ?? [:])
            default:
                try watcher.removePeer(address: address)
            }
            return Data("{}".utf8)
        default:
            throw Refusal("no such request")
        }
    }
default:
    fail(usage, code: 2)
}

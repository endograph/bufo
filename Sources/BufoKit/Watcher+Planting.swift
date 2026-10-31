import BufoContract
import Foundation

/// An operation on a bait laptop (PLAN.md, Rotation): planting, rotating,
/// or taking off a decoy, saved at each step so a crash resumes where it
/// stopped. Detection is armed before bait is written, and an old decoy is
/// taken off the laptop before it is retired.
public struct Planting: Codable, Sendable {
    public enum Step: Codable, Sendable, Equatable {
        /// Survey the laptop and make the new decoy from it.
        case plan
        /// Arm it on its detector.
        case arm
        /// Write it on the laptop.
        case write
        /// Survey again: it landed as written, and nothing else offers it.
        case verify
        /// Take a decoy off the laptop, then retire it on its detector.
        case unwrite(Bait)
        case retire(Bait)
    }

    public enum Script: Codable, Sendable, Equatable {
        case survey
        case write([BaitChange])
    }

    /// What the CLI says when it's done: planted, rotated, or unplanted.
    public var done: String
    public var destination: String
    public var detector: DetectorNames?
    public var detectorPeer: UUID?
    public var steps: [Step]
    public var adding: Bait?
    /// The new decoy's files, its private key among them, until it's verified.
    public var writes: [BaitChange]?
    /// The script the CLI was last given to run there.
    public var handedOut: Script?
    /// The detector's request id for the step in hand, so a retry is the same request.
    public var request = UUID()
    /// A name no `Host` line matches, for the survey.
    public var probe: String
    /// The write script's temporary file name on the laptop.
    public var scratch: String
    /// Why a new decoy is being taken off again.
    public var failure: String?
}

enum PlantingResult {
    case script(Data, Int32)
    case answer(String?)
}

enum PlantingNext {
    /// A script for the CLI to run on the bait laptop.
    case run(String)
    /// A request to a peer, waited for off the queue.
    case ask(peer: UUID, PeerMessage, request: UUID)
    case done(String)
}

/// Planting from this watcher, for root here through the CLI, which holds
/// the SSH access to the bait laptop and runs what it's given there. The
/// operation is the daemon's; the CLI only carries scripts and their output.
extension Watcher {
    static let answerWait: TimeInterval = 30

    /// One exchange with the CLI: `start` begins an operation (`plant`,
    /// `rotate`, `unplant`) or carries on with one (`resume`, with the last
    /// script's `output` and `status`). The reply is a script to `run` on
    /// `destination` with its pinned `hostKey`, a host key fingerprint to
    /// `confirm` first, or `done`.
    public func planting(_ request: [String: String]) throws -> [String: String] {
        var result: PlantingResult?
        switch request["start"] {
        case "plant", "rotate", "unplant":
            if let confirm = try begin(request) { return ["confirm": confirm] }
        case "resume":
            if let output = request["output"].flatMap({ Data(base64Encoded: $0) }), let status = request["status"].flatMap({ Int32($0) }) {
                result = .script(output, status)
            }
        default:
            throw Refusal("no such planting request")
        }
        while true {
            switch try queue.sync(execute: { try advance(result) }) {
            case .run(let script):
                let destination = try queue.sync { () throws -> (String, String) in
                    guard let op = store.planting, let key = store.baitHosts[Self.host(op.destination)] else {
                        throw Refusal("the bait laptop's host key isn't pinned")
                    }
                    return (op.destination, key)
                }
                return ["run": script, "destination": destination.0, "hostKey": destination.1]
            case .ask(let peer, let message, let id):
                result = .answer(try ask(peer, message, id))
            case .done(let word):
                return ["done": word]
            }
        }
    }

    /// Starts an operation: the destination checked, its host key pinned
    /// once the owner confirmed it, and the detector's names read. Returns
    /// a fingerprint for the owner to confirm, or nil once it's started.
    private func begin(_ request: [String: String]) throws -> String? {
        let start = request["start"]!, destination = request["destination"] ?? ""
        guard destination.wholeMatch(of: /([A-Za-z0-9._-]{1,64}@)?[A-Za-z0-9.-]{1,253}/) != nil else {
            throw Refusal("that isn't a bait laptop to reach over SSH: [user@]host")
        }
        let host = Self.host(destination)
        let (pinned, old, detectorAddress, detectorPeer) = try queue.sync { () throws -> (String?, Bait?, String, UUID?) in
            guard store.planting == nil else { throw Refusal("a planting is unfinished: run bufo resume first") }
            let old = store.baits.first { $0.destination == destination }
            let address: String, peer: UUID?
            switch start {
            case "plant":
                guard old == nil else { throw Refusal("a decoy from here is on that bait laptop already: rotate it") }
                address = request["detector"] ?? ""
                if let listen = store.listen, PeerTLS.same(listen.address, address) {
                    peer = nil
                } else if let pinned = store.peers.first(where: { PeerTLS.same($0.address, address) }) {
                    peer = pinned.id
                } else {
                    throw Refusal("the detector is neither this watcher's listening address nor a pinned peer")
                }
            default:
                guard let old else { throw Refusal("no decoy from here is on that bait laptop") }
                peer = old.detector
                if let id = old.detector {
                    guard let pinned = self.peer(id) else { throw Refusal("the decoy's detector is no longer a pinned peer") }
                    address = pinned.address
                } else {
                    address = store.listen?.address ?? ""
                }
            }
            return (store.baitHosts[host], old, address, peer)
        }
        var hostKey = pinned
        if hostKey == nil {
            guard let scanned = Self.hostKey(host), let fingerprint = SSHPublicKey(line: scanned)?.fingerprint else {
                throw Refusal("the bait laptop's SSH host key couldn't be read")
            }
            guard request["confirm"] == fingerprint else { return fingerprint }
            hostKey = scanned
        }
        let detector = start == "unplant" ? nil
            : DetectorNames(address: detectorAddress, dns: Self.name(of: detectorAddress), hostKey: Self.hostKey(detectorAddress))
        var steps: [Planting.Step] = start == "unplant" ? [] : [.plan, .arm, .write, .verify]
        if let old { steps += [.unwrite(old), .retire(old)] }
        func random() -> String { String((0..<12).map { _ in "abcdefghijklmnopqrstuvwxyz".randomElement()! }) }
        try queue.sync {
            guard store.planting == nil else { throw Refusal("a planting is unfinished: run bufo resume first") }
            store.baitHosts[host] = hostKey
            store.planting = Planting(done: ["plant": "planted", "rotate": "rotated"][start] ?? "unplanted", destination: destination,
                                      detector: detector, detectorPeer: detectorPeer, steps: steps, probe: random(),
                                      scratch: random())
            try saveNow()
            log.notice("began to \(start, privacy: .public) a decoy")
        }
        return nil
    }

    /// Takes the operation as far as it goes without the CLI or a peer.
    /// Failures that a retry could fix leave it saved for `resume`; a new
    /// decoy that can't be planted is taken off again and the reason given.
    func advance(_ result: PlantingResult?) throws -> PlantingNext {
        guard var op = store.planting else { throw Refusal("nothing is being planted from here") }
        var result = result
        func save() throws {
            store.planting = op
            try saveNow()
        }
        func handOut(_ script: Planting.Script) throws -> PlantingNext {
            op.handedOut = script
            try save()
            switch script {
            case .survey: return .run(BaitSurvey.script(lookups: Array(op.detector?.all ?? []).sorted(), probe: op.probe))
            case .write(let changes): return .run(BaitWrite.script(changes, scratch: op.scratch))
            }
        }
        /// The output of `script`, if `result` is it.
        func output(_ script: Planting.Script) -> (data: Data, status: Int32)? {
            guard op.handedOut == script, case .script(let data, let status)? = result else { return nil }
            result = nil
            op.handedOut = nil
            return (data, status)
        }
        func survey(_ output: (data: Data, status: Int32)) throws -> BaitSurvey {
            guard output.status == 0 else { throw Refusal("the bait laptop's survey didn't run (exit \(output.status))") }
            return try BaitSurvey(output: output.data)
        }
        func undo(_ why: String) {
            op.failure = why
            op.steps = op.adding.map { [.unwrite($0), .retire($0)] } ?? []
            op.adding = nil
            op.writes = nil
        }
        /// A failure a retry could fix: the operation stays, for `resume`.
        func pause(_ why: String) throws -> Never {
            try save()
            throw Refusal(why + "; run bufo resume to try again")
        }

        while let step = op.steps.first {
            switch step {
            case .plan:
                guard let output = output(.survey) else { return try handOut(.survey) }
                var random = SystemRandomNumberGenerator()
                do {
                    let plan = try BaitPlanner.plan(survey(output), detector: op.detector!, detectorPeer: op.detectorPeer,
                                                    destination: op.destination, makeKey: makeKey, random: &random)
                    op.adding = plan.bait
                    op.writes = plan.writes
                    op.steps.removeFirst()
                } catch {
                    op.failure = "\(error)"
                    op.steps = []
                }
            case .arm:
                let bait = op.adding!
                if let peer = bait.detector {
                    guard case .answer(let refusal)? = result else {
                        try save()
                        return .ask(peer: peer, .plant(request: op.request, account: bait.account, key: bait.key), request: op.request)
                    }
                    result = nil
                    if let refusal {
                        op.failure = "the detecting watcher refused the decoy: \(refusal)"
                        op.steps = []
                        break
                    }
                } else {
                    do {
                        try armOnce(account: bait.account, keyLine: bait.key, by: nil)
                    } catch {
                        op.failure = "this watcher refused the decoy: \(error)"
                        op.steps = []
                        break
                    }
                }
                op.request = UUID()
                op.steps.removeFirst()
            case .write:
                guard let writes = op.writes else { throw Refusal("the decoy's files are gone") }
                guard let output = output(.write(writes)) else { return try handOut(.write(writes)) }
                if let why = BaitWrite.failure(output.data, status: output.status) { undo(why) } else { op.steps.removeFirst() }
            case .verify:
                guard let output = output(.survey) else { return try handOut(.survey) }
                guard var bait = op.adding else { throw Refusal("the decoy being planted is gone") }
                let problem: String?
                do { problem = BaitPlanner.problem(bait, try survey(output)) } catch { problem = "\(error)" }
                if let problem {
                    undo(problem)
                } else {
                    // A rotation's new decoy takes over the old one's known_hosts line
                    // when both look the detector up by the same name.
                    for (index, step) in op.steps.enumerated() {
                        guard case .unwrite(var old) = step, bait.knownLine == nil, old.knownLine != nil,
                              old.lookup.lowercased() == bait.lookup.lowercased() else { continue }
                        bait.knownLine = old.knownLine
                        old.knownLine = nil
                        op.steps[index] = .unwrite(old)
                    }
                    bait.planted = Date()
                    store.baits.append(bait)
                    op.adding = nil
                    op.writes = nil
                    op.steps.removeFirst()
                    log.notice("planted a decoy")
                }
            case .unwrite(let bait):
                if let output = output(.survey) {
                    let changes: [BaitChange]
                    do { changes = try BaitPlanner.removal(bait, try survey(output)) } catch { try pause("\(error)") }
                    if !changes.isEmpty { return try handOut(.write(changes)) }
                    op.steps.removeFirst()
                } else if case .write(let changes)? = op.handedOut, let output = output(.write(changes)) {
                    if let why = BaitWrite.failure(output.data, status: output.status) { try pause(why) }
                    op.steps.removeFirst()
                } else {
                    return try handOut(.survey)
                }
            case .retire(let bait):
                if let peer = bait.detector {
                    guard case .answer(let refusal)? = result else {
                        try save()
                        return .ask(peer: peer, .retire(request: op.request, account: bait.account), request: op.request)
                    }
                    result = nil
                    if let refusal { try pause("the detecting watcher didn't retire a decoy: \(refusal)") }
                } else if store.decoys.contains(where: { $0.account == bait.account }) {
                    do { try retire(account: bait.account, by: nil) } catch { try pause("\(error)") }
                }
                store.baits.removeAll { $0.id == bait.id }
                op.request = UUID()
                op.steps.removeFirst()
            }
            try save()
        }
        store.planting = nil
        try saveNow()
        if let failure = op.failure {
            log.error("a planting stopped: \(failure, privacy: .public)")
            throw Refusal(failure)
        }
        log.notice("\(op.done, privacy: .public) a decoy")
        return .done(op.done)
    }

    /// Sends a planting request to a peer and waits off the queue for its answer.
    private func ask(_ peer: UUID, _ message: PeerMessage, _ request: UUID) throws -> String? {
        let answer = Answer()
        let sent = queue.sync { () -> Bool in
            guard let link = links[peer] else { return false }
            answers[request] = (peer, { refusal in
                answer.refusal = refusal
                answer.done.signal()
            })
            link.send(message)
            return true
        }
        guard sent else { throw Refusal("the detecting watcher isn't connected; run bufo resume once it is") }
        guard answer.done.wait(timeout: .now() + Self.answerWait) == .success else {
            queue.sync { answers[request] = nil }
            throw Refusal("the detecting watcher didn't answer; run bufo resume to try again")
        }
        return answer.refusal
    }

    private final class Answer: @unchecked Sendable {
        let done = DispatchSemaphore(value: 0)
        var refusal: String?
    }

    /// A key pair made in the root-only state directory and read back; nothing is left there.
    private func makeKey(type: String, bits: Int, format: String, comment: String) throws -> (privateKey: Data, publicFile: Data) {
        let directory = state + "/.key-" + UUID().uuidString
        guard mkdir(directory, 0o700) == 0 else { throw Refusal("a key couldn't be made: \(System.lastError)") }
        defer { try? FileManager.default.removeItem(atPath: directory) }
        var arguments = ["-q", "-t", type, "-b", "\(bits)", "-N", "", "-C", comment, "-f", directory + "/key"]
        if format != "OpenSSH" { arguments += ["-m", format] }
        guard System.run("/usr/bin/ssh-keygen", arguments).status == 0,
              let privateKey = System.read(directory + "/key"), let publicFile = System.read(directory + "/key.pub") else {
            throw Refusal("ssh-keygen couldn't make a key")
        }
        return (privateKey, publicFile)
    }

    static func host(_ destination: String) -> String {
        String(destination.split(separator: "@").last ?? "")
    }

    /// `host`'s SSH host key, `<type> <base64>`, the strongest kind it offers.
    static func hostKey(_ host: String) -> String? {
        let output = System.run("/usr/bin/ssh-keyscan", ["-T", "5", "-t", "ed25519,ecdsa,rsa", "--", host], timeout: 15).output
        let lines = String(decoding: output, as: UTF8.self).split(separator: "\n").compactMap { line -> SSHPublicKey? in
            let fields = line.split(separator: " ")
            return fields.count >= 3 ? SSHPublicKey(line: fields.dropFirst().joined(separator: " ")) : nil
        }
        for type in ["ssh-ed25519", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", "ssh-rsa"] {
            if let key = lines.first(where: { $0.type == type }) { return key.line }
        }
        return nil
    }

    /// The name an address has in DNS, which on a tailnet is its MagicDNS name.
    static func name(of address: String) -> String? {
        var hints = addrinfo(ai_flags: AI_NUMERICHOST, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM, ai_protocol: 0,
                             ai_addrlen: 0, ai_canonname: nil, ai_addr: nil, ai_next: nil)
        var info: UnsafeMutablePointer<addrinfo>?
        guard getaddrinfo(address, nil, &hints, &info) == 0, let info else { return nil }
        defer { freeaddrinfo(info) }
        var host = [CChar](repeating: 0, count: Int(NI_MAXHOST))
        guard getnameinfo(info.pointee.ai_addr, info.pointee.ai_addrlen, &host, socklen_t(host.count), nil, 0, NI_NAMEREQD) == 0 else {
            return nil
        }
        let name = String(decoding: host.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
        return name.hasSuffix(".") ? String(name.dropLast()) : name
    }
}

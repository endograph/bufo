import BufoContract
import Foundation
import Security

/// Hosts (PLAN.md, The host contract): pinning by root here, and each
/// host's calls, served only in its own namespace.
extension Watcher {
    /// Updates handed to a host per call.
    static let hostBatch = 64
    /// The longest a host's `updates` waits for something new.
    static let hostWait: TimeInterval = 25

    // MARK: Pinning, by root here

    /// Pins the app `requirement` names, run as `user`, as the host `name`.
    public func addHost(name: String, requirement: String, user: String) throws {
        guard name.wholeMatch(of: PinnedHost.names) != nil else { throw Refusal("that isn't a host name: letters, digits, . _ -") }
        let canonical = try PinnedHost.canonical(requirement)
        let id = System.run("/usr/bin/id", ["-u", "--", user])
        guard id.status == 0, let uid = uid_t(String(decoding: id.output, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw Refusal("no such user")
        }
        try queue.sync {
            guard !store.hosts.contains(where: { $0.name == name }) else { throw Refusal("a host by that name is pinned already") }
            let all = Service.either(try Signature.ofSelf().requirement, store.hosts.map(\.requirement) + [canonical])
            var combined: SecRequirement?
            guard SecRequirementCreateWithString(all as CFString, [], &combined) == errSecSuccess else {
                throw Refusal("that code-signing requirement doesn't combine with the others")
            }
            let host = PinnedHost(name: name, requirement: canonical, user: uid)
            store.hosts.append(host)
            store.ledger.add(recipient: host.recipient)
            try saveNow()
            log.notice("pinned the host \(name, privacy: .public)")
        }
    }

    /// Unpins a host. Incidents it reported stay.
    public func removeHost(name: String) throws {
        try queue.sync {
            guard let host = store.hosts.first(where: { $0.name == name }) else { throw Refusal("no host has that name") }
            store.hosts.removeAll { $0.name == name }
            store.ledger.remove(recipient: host.recipient)
            try saveNow()
            log.notice("unpinned the host \(name, privacy: .public)")
        }
    }

    /// Who may call as a host, for the service.
    public var hostIdentities: [Service.HostIdentity] {
        queue.sync { store.hosts.map { Service.HostIdentity(id: $0.id, requirement: $0.requirement, user: $0.user) } }
    }

    // MARK: A host's calls

    /// Serves one call from the host pinned as `id`, in its own namespace only.
    public func host(_ id: UUID, _ request: [String: String]) throws -> Data {
        guard let name = queue.sync(execute: { store.hosts.first { $0.id == id }?.name }) else { throw Refusal("this host isn't pinned now") }
        switch request["request"] {
        case "status":
            return try JSONEncoder().encode(status())
        case "updates":
            // One waiting poll per host: another meanwhile answers at once, so
            // hosts can't hold more of the daemon's threads than there are hosts.
            var wait = min(max(Double(request["wait"] ?? "") ?? 0, 0), Self.hostWait)
            if wait > 0, !queue.sync(execute: { polling.insert(id).inserted }) { wait = 0 }
            defer { if wait > 0 { _ = queue.sync { polling.remove(id) } } }
            let until = Date().addingTimeInterval(wait)
            // Asking is kept with the next save, not saved for itself: it is
            // read only against this watcher's own start (`delivering`).
            try queue.sync { try updateHost(name, save: false) { $0.lastSeen = Date() } }
            while true {
                let batch = try queue.sync {
                    guard let host = store.hosts.first(where: { $0.name == name }) else { throw Refusal("no such host") }
                    // Only what is saved: a host may keep it, and it mustn't outlive a crash here.
                    return Array(store.ledger.pending(for: host.recipient).filter { $0.stamp <= savedThrough }.prefix(Self.hostBatch))
                }
                if !batch.isEmpty || Date() >= until { return try JSONEncoder().encode(batch) }
                Thread.sleep(forTimeInterval: 0.5)
            }
        case "ack":
            guard let stamp = request["through"].flatMap({ UInt64($0) }) else { throw Refusal("no stamp") }
            try queue.sync {
                try updateHost(name) { $0.lastAck = Date() }
                store.ledger.ack(store.hosts.first { $0.name == name }!.recipient, through: stamp)
            }
        case "delivery":
            guard let stage = request["stage"].flatMap(DeliveryStage.init) else { throw Refusal("no such stage") }
            try queue.sync {
                try updateHost(name) {
                    $0.lastStage = stage
                    $0.lastStageAt = Date()
                }
            }
        case "register":
            guard let id = request["decoy"].flatMap(UUID.init) else { throw Refusal("that isn't a decoy id") }
            try queue.sync {
                guard let index = store.hosts.firstIndex(where: { $0.name == name }) else { throw Refusal("no such host") }
                try store.hosts[index].register(id)
                try saveNow()
            }
        case "presented":
            guard let id = request["decoy"].flatMap(UUID.init) else { throw Refusal("that isn't a decoy id") }
            let source = String((request["source"] ?? "").prefix(256))
            try queue.sync {
                guard let host = store.hosts.first(where: { $0.name == name }) else { throw Refusal("no such host") }
                let decoy = try host.decoy(id)
                let address = Self.isAddress(source) ? source : nil
                let (incident, alarms) = store.book.record(
                    decoy: decoy, kind: .hostCredential, source: Source(address: address, name: address == nil ? source : nil, reportedBy: name),
                    connection: nil, at: Date())
                store.ledger.accept(.incident(incident))
                alarms.forEach(raise)
                try saveNow()
                deliver()
            }
        default:
            throw Refusal("no such request for a host")
        }
        return Data("{}".utf8)
    }

    private func updateHost(_ name: String, save: Bool = true, _ change: (inout PinnedHost) -> Void) throws {
        guard let index = store.hosts.firstIndex(where: { $0.name == name }) else { throw Refusal("no such host") }
        change(&store.hosts[index])
        if save { dirty = true }
    }

    /// How long a host that takes updates may go without asking before
    /// delivery is down (PLAN.md, Delivery health).
    static let deliveryQuiet: TimeInterval = 900

    /// Whether this watcher's alarms are getting out through its hosts: nil
    /// when none here has taken updates (a host that only reports, or none),
    /// else whether one asked within 15 minutes of now, or of this watcher's
    /// own start or stall, and didn't last report a failure.
    func delivering() -> Bool? {
        Self.delivering(store.hosts, awake: awake, now: Date())
    }

    static func delivering(_ hosts: [PinnedHost], awake: Date, now: Date) -> Bool? {
        let takers = hosts.compactMap { host in host.lastSeen.map { (asked: max($0, awake), failed: host.lastStage == .failed) } }
        guard !takers.isEmpty else { return nil }
        return takers.contains { now.timeIntervalSince($0.asked) < deliveryQuiet && !$0.failed }
    }

    func hostStatuses() -> [HostStatus] {
        store.hosts.map { host in
            HostStatus(name: host.name, lastSeen: host.lastSeen, lastAck: host.lastAck,
                       unacked: store.ledger.pending(for: host.recipient).count, registered: host.registered.count,
                       lastStage: host.lastStage, lastStageAt: host.lastStageAt)
        }
    }
}

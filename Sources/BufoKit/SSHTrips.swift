import BufoContract
import Foundation

/// An SSH decoy as the detecting watcher knows it: the account its key opens
/// and the key's fingerprint. Placement data: it stays in the store.
public struct SSHDecoy: Codable, Sendable, Hashable, Identifiable {
    public var id: UUID
    public var account: String
    public var uid: UInt32
    public var fingerprint: String
    /// The peer that armed it under the planting grant; nil when root here did.
    public var armedBy: UUID?

    public init(id: UUID, account: String, uid: UInt32, fingerprint: String, armedBy: UUID? = nil) {
        self.id = id
        self.account = account
        self.uid = uid
        self.fingerprint = fingerprint
        self.armedBy = armedBy
    }
}

/// One use of a decoy: the first of a connection's lines that names it.
public struct Trip: Sendable, Equatable {
    public var decoy: UUID
    public var at: Date
    public var address: String?
    public var port: Int?
    /// The connection: the sshd process that served it and when it began, so
    /// a reused process id is another connection.
    public var connection: String
    /// The line itself, kept only as local evidence.
    public var evidence: String
}

/// Turns sshd's log events into trips. A connection logs several lines
/// naming the decoy (the key found, postponed, failed, PAM's refusal); it is
/// one trip. The self-test's key is exempt once, by its exact fingerprint,
/// and only while it is expected.
///
/// State lives in memory. After a restart, the detector feeds the lines from
/// a connection window before its last-seen line again and drops their
/// outcomes, so connections it already counted aren't counted twice.
public struct SSHTripMatcher: Sendable {
    public enum Outcome: Equatable, Sendable {
        case trip(Trip)
        case probeSeen(fingerprint: String)
        case nothing
    }

    public var decoys: [SSHDecoy]
    public var sshd: SSHDIdentity
    private var probes: [String: Date] = [:]
    private var connections: [Int32: Connection] = [:]

    struct Connection {
        var began: Date
        var seen: Date
        var address: String?
        var port: Int?
        var tripped: Set<UUID> = []
    }

    /// How long a connection's lines are tied together by its process id:
    /// well past sshd's two-minute login grace time.
    static let connectionWindow: TimeInterval = 600
    static let maxConnections = 512

    public init(decoys: [SSHDecoy], sshd: SSHDIdentity) {
        self.decoys = decoys
        self.sshd = sshd
    }

    /// The self-test is about to offer this fingerprint; its line is exempt
    /// once, until `deadline`.
    public mutating func expectProbe(_ fingerprint: String, until deadline: Date) {
        probes[fingerprint] = deadline
    }

    /// Probes whose line never came: each is a failed self-test.
    public mutating func overdueProbes(now: Date) -> [String] {
        let overdue = probes.filter { $0.value < now }.map(\.key)
        for fingerprint in overdue { probes[fingerprint] = nil }
        return overdue
    }

    public mutating func consume(_ event: LogEvent) -> Outcome {
        guard sshd.admits(event, accountUIDs: Set(decoys.map(\.uid))), let line = SSHLine.parse(event.eventMessage) else {
            return .nothing
        }
        forget(before: event.timestamp.addingTimeInterval(-Self.connectionWindow))
        let pid = event.processID
        if case .connection(let address, let port) = line {
            // A connection begins: anything held for this process id was another's.
            connections[pid] = Connection(began: event.timestamp, seen: event.timestamp, address: address, port: port)
            return .nothing
        }
        var connection = connections[pid] ?? Connection(began: event.timestamp, seen: event.timestamp)
        connection.seen = event.timestamp
        if connection.address == nil, let source = line.source { (connection.address, connection.port) = source }
        defer { connections[pid] = connection }
        // A decoy is checked first, so no expected probe can ever exempt one.
        guard let decoy = decoys.first(where: { $0.fingerprint == line.fingerprint })
            ?? decoys.first(where: { $0.account == line.user }) else {
            if let fingerprint = line.fingerprint, let deadline = probes[fingerprint], deadline >= event.timestamp {
                probes[fingerprint] = nil
                return .probeSeen(fingerprint: fingerprint)
            }
            return .nothing
        }
        guard connection.tripped.insert(decoy.id).inserted else { return .nothing }
        return .trip(Trip(decoy: decoy.id, at: event.timestamp, address: connection.address, port: connection.port,
                          connection: "\(pid)@\(connection.began.timeIntervalSince1970)", evidence: event.eventMessage))
    }

    private mutating func forget(before cutoff: Date) {
        connections = connections.filter { $0.value.seen >= cutoff }
        if connections.count > Self.maxConnections {
            let keep = connections.sorted { $0.value.seen > $1.value.seen }.prefix(Self.maxConnections)
            connections = Dictionary(uniqueKeysWithValues: keep.map { ($0.key, $0.value) })
        }
    }
}

import Foundation

/// What a decoy is, never what it became (ARCHITECTURE.md, Terms).
public enum DecoyKind: String, Codable, Sendable, CaseIterable {
    /// A key on a bait machine, detected by sshd on a watcher.
    case sshKey = "ssh-key"
    /// A host's own credential that authorizes nothing, reported by the host.
    case hostCredential = "host-credential"
}

/// Who used a decoy, as far as anyone can say.
public struct Source: Codable, Sendable, Hashable {
    /// A network address (a tailnet node's), or nil when none is known.
    public var address: String?
    /// A name for the source, when something resolved one (a node, a peer).
    public var name: String?
    /// The host that reported the trip, or nil when the watcher saw it itself.
    public var reportedBy: String?

    public init(address: String?, name: String? = nil, reportedBy: String? = nil) {
        self.address = address
        self.name = name
        self.reportedBy = reportedBy
    }
}

/// A decoy's trips from one source, as any host or peer may see it: the
/// kind, never the placement, the account, or the fingerprint. An incident
/// is state; an `Alarm` is what the owner hears about it.
public struct Incident: Codable, Sendable, Identifiable, Hashable {
    public var id: UUID
    /// Each change to the incident raises it, so a receiver keeps the newest.
    public var revision: UInt64
    public var kind: DecoyKind
    /// The watcher that detected it.
    public var watcher: UUID
    public var source: Source
    public var firstSeen: Date
    public var lastSeen: Date
    /// Every trip, counted before any budget is consulted.
    public var count: UInt64
    /// Distinct connections among them.
    public var connections: UInt64
    /// Closed only by root at the watcher, never by quiet.
    public var closed: Date?

    public init(id: UUID, revision: UInt64, kind: DecoyKind, watcher: UUID, source: Source, firstSeen: Date,
                lastSeen: Date, count: UInt64, connections: UInt64, closed: Date?) {
        self.id = id
        self.revision = revision
        self.kind = kind
        self.watcher = watcher
        self.source = source
        self.firstSeen = firstSeen
        self.lastSeen = lastSeen
        self.count = count
        self.connections = connections
        self.closed = closed
    }
}

/// Which budget an alarm draws on, so one source of trips can't use up
/// another's (PLAN.md, Incidents, alarms, and health).
public enum AlarmBudget: Hashable, Codable, Sendable {
    /// Trips this watcher saw itself.
    case observed
    /// Trips one host reported.
    case host(String)
    /// Silence and degraded coverage.
    case health
}

/// Why an incident alarmed (PLAN.md, Incidents, alarms, and health).
public enum AlarmReason: String, Codable, Sendable {
    case opened
    /// The 10th or 100th trip.
    case repeated
    /// A new connection after an hour's quiet.
    case resumed
    /// Daily, while the incident stays active.
    case reminder
}

/// One thing the owner should hear, decided once by one watcher. Each takes
/// the next number in that watcher's sequence, so a receiver that sees a gap
/// knows an alarm was lost. It carries what it is about as it stood then,
/// so it can be shown on its own.
public struct Alarm: Codable, Sendable, Hashable {
    /// The watcher that decided it.
    public var watcher: UUID
    public var sequence: UInt64
    public var at: Date
    public var subject: Subject

    public enum Subject: Codable, Sendable, Hashable {
        case incident(Incident, AlarmReason)
        /// This many of a budget's alarms were held back in the last hour;
        /// their incidents were recorded and delivered all the same.
        case heldBack(AlarmBudget, count: Int)
        /// A peer watcher went quiet, said it was stopping, reported degraded
        /// coverage, or came back: its id once known, and its address.
        case peer(watcher: UUID?, address: String, PeerChange)
    }

    public init(watcher: UUID, sequence: UInt64, at: Date, subject: Subject) {
        self.watcher = watcher
        self.sequence = sequence
        self.at = at
        self.subject = subject
    }
}

/// What a watcher delivers to a peer or a host, in order and at least once:
/// an incident's newest revision, or an alarm. A receiver keeps the newest
/// revision of each incident, and each alarm once.
public enum Update: Codable, Sendable, Hashable {
    case incident(Incident)
    case alarm(Alarm)

    /// The watcher it came from: the one that detected the incident, or
    /// decided the alarm.
    public var watcher: UUID {
        switch self {
        case .incident(let incident): incident.watcher
        case .alarm(let alarm): alarm.watcher
        }
    }
}

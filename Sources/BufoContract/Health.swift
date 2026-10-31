import Foundation

/// What a watcher tells its peers every minute (PLAN.md, Messages): enough
/// to know it is alive, seeing, and not missing alarms. No placement.
public struct Health: Codable, Sendable, Equatable {
    public var watcher: UUID
    /// This run of the daemon: its boot and start, so a restart is seen.
    public var instance: String
    /// Grows with each health this instance sends.
    public var sequence: UInt64
    public var coverage: Coverage
    public var lastSelfTest: Date?
    public var kinds: [DecoyKind]
    /// The last number in its alarm sequence.
    public var latestAlarm: UInt64
    /// Whether its hosts are taking updates; nil when none here takes them.
    public var delivering: Bool?

    public init(watcher: UUID, instance: String, sequence: UInt64, coverage: Coverage, lastSelfTest: Date?,
                kinds: [DecoyKind], latestAlarm: UInt64, delivering: Bool?) {
        self.watcher = watcher
        self.instance = instance
        self.sequence = sequence
        self.coverage = coverage
        self.lastSelfTest = lastSelfTest
        self.kinds = kinds
        self.latestAlarm = latestAlarm
        self.delivering = delivering
    }
}

/// What changed about a peer, as an alarm says it (PLAN.md, Health).
public enum PeerChange: String, Codable, Sendable {
    /// No health for 5 minutes.
    case silent
    /// No health for 5 minutes after it said it was stopping (a shutdown,
    /// a restart, or root saying so).
    case stopped
    /// Heard again after silent or stopped.
    case back
    /// It reports degraded coverage.
    case degraded
    /// Its coverage is full again after degraded.
    case covered
    /// Its hosts stopped taking updates, or report failing to deliver them.
    case undelivered
    /// Its hosts deliver again after undelivered.
    case delivering
}

/// A peer as this watcher sees it.
public struct PeerStatus: Codable, Sendable, Equatable {
    public var address: String
    /// Its id, once it has sent health.
    public var watcher: UUID?
    public var connected: Bool
    public var lastHealth: Date?
    public var coverage: Coverage?
    /// Quiet past the silence threshold.
    public var silent: Bool
    /// Whether it may arm decoys here.
    public var mayPlant: Bool
    /// This watcher's updates it hasn't acked.
    public var unacked: Int
    /// The last alarm it says it raised, and the last of its alarms this
    /// watcher holds: equal when none is missing.
    public var latestAlarm: UInt64?
    public var alarmsTaken: UInt64

    public init(address: String, watcher: UUID?, connected: Bool, lastHealth: Date?, coverage: Coverage?, silent: Bool,
                mayPlant: Bool, unacked: Int, latestAlarm: UInt64?, alarmsTaken: UInt64) {
        self.address = address
        self.watcher = watcher
        self.connected = connected
        self.lastHealth = lastHealth
        self.coverage = coverage
        self.silent = silent
        self.mayPlant = mayPlant
        self.unacked = unacked
        self.latestAlarm = latestAlarm
        self.alarmsTaken = alarmsTaken
    }
}

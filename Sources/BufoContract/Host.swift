import Foundation

/// An update as a host or peer gets it: the watcher's ledger stamp, which
/// the receiver acks once it has stored everything through it, and the update.
public struct Stamped: Codable, Sendable, Equatable {
    public var stamp: UInt64
    public var update: Update

    public init(stamp: UInt64, update: Update) {
        self.stamp = stamp
        self.update = update
    }
}

/// How far a host got an alarm toward the owner (PLAN.md, The API), which
/// Bufo keeps as delivery health.
public enum DeliveryStage: String, Codable, Sendable, CaseIterable {
    case stored, submitted, accepted, opened, failed
}

/// A pinned host as `status` shows it: no placement.
public struct HostStatus: Codable, Sendable, Equatable {
    public var name: String
    public var lastSeen: Date?
    public var lastAck: Date?
    /// Updates it hasn't acked.
    public var unacked: Int
    /// Its own decoys it registered.
    public var registered: Int
    public var lastStage: DeliveryStage?
    public var lastStageAt: Date?

    public init(name: String, lastSeen: Date?, lastAck: Date?, unacked: Int, registered: Int, lastStage: DeliveryStage?,
                lastStageAt: Date?) {
        self.name = name
        self.lastSeen = lastSeen
        self.lastAck = lastAck
        self.unacked = unacked
        self.registered = registered
        self.lastStage = lastStage
        self.lastStageAt = lastStageAt
    }
}

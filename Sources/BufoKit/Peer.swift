import BufoContract
import Foundation

/// A watcher this one trades its ledger and health with (PLAN.md, Watcher
/// to watcher), pinned by root here with `bufo peer add`.
public struct Peer: Codable, Sendable {
    public var id: UUID
    /// Its tailnet address: the only source it's taken from, and where it is dialed.
    public var address: String
    /// Dialed at this port when set; otherwise it dials here.
    public var port: UInt16?
    /// The pair's PSK identity (hex) and key.
    public var identity: String
    public var key: Data
    /// The planting grant: it may arm a few SSH decoy accounts here and
    /// retire its own (ARCHITECTURE.md).
    public var mayPlant: Bool
    public var pinned: Date
    /// Its id, from its first health; any other later is refused.
    public var watcher: UUID?
    public var lastHealth: Date?
    public var health: Health?
    /// It said it was stopping, since it was last heard.
    public var stopping = false
    /// An alarm said it was silent or stopped, degraded, or undelivered, and
    /// none yet that it's back, covered, or delivering.
    public var silent = false
    public var degraded = false
    public var undelivered = false

    var code: PairingCode { PairingCode(identity: identity, key: key) }
    var recipient: String { "peer \(id.uuidString)" }

    init(address: String, port: UInt16?, code: PairingCode, mayPlant: Bool) {
        id = UUID()
        self.address = address
        self.port = port
        identity = code.identity
        key = code.key
        self.mayPlant = mayPlant
        pinned = Date()
    }
}

/// Where a watcher listens for peers: its tailnet address and its install's port.
public struct Listener: Codable, Sendable, Equatable {
    public var address: String
    public var port: UInt16
}

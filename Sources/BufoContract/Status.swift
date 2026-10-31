import Foundation

/// Whether a detector is seeing everything it should.
public enum Coverage: String, Codable, Sendable {
    /// Streaming, with nothing missed since it began.
    case full
    /// A gap it couldn't read back, a stream that ended, or a failed self-test.
    case degraded
    /// Not running.
    case off
}

extension DecoyKind: CodingKeyRepresentable {}

/// A watcher as `bufo status` and a host see it: no placement. Everything
/// but `installed` is absent when Bufo isn't installed.
public struct Status: Codable, Sendable, Equatable {
    public var installed: Bool
    public var watcher: UUID?
    /// The running build's version.
    public var version: Int?
    public var kinds: [DecoyKind]?
    public var coverage: Coverage?
    /// When the detector last saw its own self-test come back.
    public var lastSelfTest: Date?
    /// Incidents still open, this watcher's and its peers', by kind.
    public var openIncidents: [DecoyKind: Int]?
    public var peers: [PeerStatus]?
    /// SSH decoys planted on bait laptops from here.
    public var baits: Int?
    public var hosts: [HostStatus]?
    /// Whether the hosts here that take updates are taking them and
    /// delivering; nil when none does (PLAN.md, Delivery health).
    public var delivering: Bool?
    /// What this watcher can't do and says so (no Secure Enclave, a store
    /// kept unencrypted until v1).
    public var notes: [String]?

    public init(installed: Bool, watcher: UUID? = nil, version: Int? = nil, kinds: [DecoyKind]? = nil,
                coverage: Coverage? = nil, lastSelfTest: Date? = nil, openIncidents: [DecoyKind: Int]? = nil,
                peers: [PeerStatus]? = nil, baits: Int? = nil, hosts: [HostStatus]? = nil,
                delivering: Bool? = nil, notes: [String]? = nil) {
        self.installed = installed
        self.watcher = watcher
        self.version = version
        self.kinds = kinds
        self.coverage = coverage
        self.lastSelfTest = lastSelfTest
        self.openIncidents = openIncidents
        self.peers = peers
        self.baits = baits
        self.hosts = hosts
        self.delivering = delivering
        self.notes = notes
    }

    public static let notInstalled = Status(installed: false)
}

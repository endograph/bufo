import BufoContract
import Foundation

/// Everything a watcher keeps across restarts, in one file in its root-only
/// state directory, replaced whole on each save (PLAN.md, The store's key:
/// unencrypted until v1, and `status` says so). Placements live here and
/// nowhere else.
public struct Store: Codable, Sendable {
    public var decoys: [SSHDecoy] = []
    public var book: IncidentBook
    public var ledger = Ledger()
    /// The first lines that tripped each incident, kept only here.
    public var evidence: [UUID: [String]] = [:]
    /// The last sshd line the detector took, where a restart picks up.
    public var lastSeen: LogMark?
    /// When the first decoy was armed, where history starts with no line taken yet.
    public var armedAt: Date?
    /// Bufo's file in `sshd_config.d`.
    public var sshdFile: String?
    /// Why coverage is degraded, kept until a self-test passes.
    public var coverageProblem: String?
    /// The built-in account the self-test offers its keys for.
    public var selfTestAccount: String?
    public var lastSelfTest: Date?
    /// The watchers this one trades with, and where it listens for them.
    public var peers: [Peer] = []
    public var listen: Listener?
    /// SSH decoys planted on bait laptops from here, and the operation
    /// planting, rotating, or taking one off, saved at each step.
    public var baits: [Bait] = []
    public var planting: Planting?
    /// Each bait laptop's SSH host key, pinned when the owner confirmed it.
    public var baitHosts: [String: String] = [:]
    /// Apps pinned as hosts.
    public var hosts: [PinnedHost] = []

    static let evidenceLines = 20

    public init(watcher: UUID) {
        book = IncidentBook(watcher: watcher)
    }

    static func path(_ state: String) -> String { state + "/store.json" }

    /// The store in `state`, or a new one for `watcher` when there is none yet.
    public static func load(_ state: String, watcher: UUID) throws -> Store {
        let state = try rootsAloneDirectory(state)
        guard System.exists(path(state)) else { return Store(watcher: watcher) }
        guard let data = System.read(path(state), limit: 256 * 1024 * 1024),
              let store = try? JSONDecoder().decode(Store.self, from: data) else {
            throw Refusal("the store doesn't read")
        }
        return store
    }

    public func save(_ state: String) throws {
        try System.replace(Self.path(try rootsAloneDirectory(state)), with: try JSONEncoder().encode(self), mode: 0o600)
    }
}

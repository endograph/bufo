import BufoContract
import CryptoKit
import Foundation
import Security

/// An app pinned by root here as a host (PLAN.md, The host contract): one
/// code-signing requirement and one local user. It gets every update past
/// its own cursor, and reports presentations of decoys it registered, under
/// ids that are its own: Bufo keeps them apart from every other host's.
public struct PinnedHost: Codable, Sendable {
    /// This pinning: a host removed and pinned again under the same name is another.
    public var id = UUID()
    public var name: String
    public var requirement: String
    public var user: uid_t
    public var pinned: Date
    /// Its decoy ids, as it gave them.
    public var registered: [UUID: Date] = [:]
    public var lastSeen: Date?
    public var lastAck: Date?
    public var lastStage: DeliveryStage?
    public var lastStageAt: Date?

    /// Decoys a host may register.
    static let maxRegistered = 16

    init(name: String, requirement: String, user: uid_t) {
        self.name = name
        self.requirement = requirement
        self.user = user
        pinned = Date()
    }

    var recipient: String { "host " + name }

    /// `requirement` as macOS writes it back once compiled: no comments,
    /// so it can't reach past the parentheses it's joined in (`Service.either`).
    static func canonical(_ requirement: String) throws -> String {
        var compiled: SecRequirement?, text: CFString?
        guard SecRequirementCreateWithString(requirement as CFString, [], &compiled) == errSecSuccess, let compiled,
              SecRequirementCopyString(compiled, [], &text) == errSecSuccess, let canonical = text as String? else {
            throw Refusal("that code-signing requirement doesn't compile")
        }
        return canonical
    }

    /// Names root may pin a host by: also its budget's and its reports' name.
    nonisolated(unsafe) static let names = /[A-Za-z0-9][A-Za-z0-9._-]{0,31}/

    /// Registers `id`; again is the same. Past the cap, refused.
    mutating func register(_ id: UUID) throws {
        guard registered[id] == nil else { return }
        guard registered.count < Self.maxRegistered else {
            throw Refusal("this host has registered \(Self.maxRegistered) decoys already")
        }
        registered[id] = Date()
    }

    /// The decoy Bufo records a presentation of `id` against: refused unless
    /// this host registered it, and never the same as another host's.
    func decoy(_ id: UUID) throws -> UUID {
        guard registered[id] != nil else { throw Refusal("that isn't a decoy this host registered") }
        var bytes = Array(SHA256.hash(data: Data((name + "\u{0}" + id.uuidString).utf8)).prefix(16))
        bytes[6] = bytes[6] & 0x0F | 0x50
        bytes[8] = bytes[8] & 0x3F | 0x80
        return UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
                           bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
    }
}

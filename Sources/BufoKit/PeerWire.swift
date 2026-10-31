import BufoContract
import Foundation

/// What watchers say to each other (PLAN.md, Messages), one per frame.
/// The dialer's first frame is not one of these: it is the proof alone,
/// 32 bytes, read before anything is parsed.
enum PeerMessage: Codable, Equatable {
    case health(Health)
    /// The sender's own ledger entries, oldest first.
    case updates([Ledger.Entry])
    /// The receiver has stored everything through this stamp.
    case ack(UInt64)
    /// The sender is being told to stop.
    case stopping
    /// The planting grant: arm a decoy account for this public key, or
    /// retire one this peer armed. The only placement data that crosses.
    case plant(request: UUID, account: String, key: String)
    case retire(request: UUID, account: String)
    /// Nil when done, or why not.
    case answer(request: UUID, refusal: String?)
}

/// Frames on a peer connection: a 4-byte big-endian length, then that many
/// bytes: the proof first, then JSON messages. A length of zero or over
/// `maxFrame` ends the connection; nothing is buffered past one frame.
struct FrameReader {
    static let maxFrame = 64 * 1024
    private var buffer = Data()

    enum Failure: Error { case oversized, malformed }

    /// Takes bytes off the wire; returns each whole frame's body, or fails.
    mutating func take(_ data: Data) throws -> [Data] {
        buffer += data
        var bodies: [Data] = []
        while buffer.count >= 4 {
            let length = buffer.prefix(4).reduce(0) { $0 << 8 | Int($1) }
            guard length > 0, length <= Self.maxFrame else { throw Failure.oversized }
            guard buffer.count >= 4 + length else { break }
            bodies.append(Data(buffer.dropFirst(4).prefix(length)))
            buffer = Data(buffer.dropFirst(4 + length))
        }
        return bodies
    }

    static func message(_ body: Data) throws -> PeerMessage {
        guard let message = try? JSONDecoder().decode(PeerMessage.self, from: body) else { throw Failure.malformed }
        return message
    }

    static func frame(_ message: PeerMessage) -> Data? {
        (try? JSONEncoder().encode(message)).flatMap(frame(body:))
    }

    static func frame(body: Data) -> Data? {
        guard !body.isEmpty, body.count <= maxFrame else { return nil }
        let length = UInt32(body.count).bigEndian
        return withUnsafeBytes(of: length) { Data($0) } + body
    }
}

/// A peer's pairing code: the PSK identity and key both sides pin, made on
/// one side and typed on the other once.
struct PairingCode: Equatable {
    var identity: String
    var key: Data

    static func make() -> PairingCode {
        PairingCode(identity: random(16).map { String(format: "%02x", $0) }.joined(), key: random(32))
    }

    init(identity: String, key: Data) {
        self.identity = identity
        self.key = key
    }

    init?(_ text: String) {
        var base64 = text.trimmingCharacters(in: .whitespacesAndNewlines)
            .replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        base64 += String(repeating: "=", count: (4 - base64.count % 4) % 4)
        guard let data = Data(base64Encoded: base64), data.count == 48 else { return nil }
        identity = data.prefix(16).map { String(format: "%02x", $0) }.joined()
        key = data.suffix(32)
    }

    var text: String {
        let identityBytes = stride(from: 0, to: identity.count, by: 2).compactMap {
            UInt8(identity.dropFirst($0).prefix(2), radix: 16)
        }
        return (Data(identityBytes) + key).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    private static func random(_ count: Int) -> Data {
        var bytes = [UInt8](repeating: 0, count: count)
        precondition(SecRandomCopyBytes(kSecRandomDefault, count, &bytes) == errSecSuccess)
        return Data(bytes)
    }
}

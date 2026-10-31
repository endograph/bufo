import CryptoKit
import Foundation

/// An OpenSSH public key as `authorized_keys` and a `.pub` file hold it:
/// its type and the blob, which names the same type inside it. Any comment
/// is dropped. Placement data: it stays in the store and the decoy's account.
public struct SSHPublicKey: Equatable, Sendable {
    public var type: String
    public var blob: Data

    /// Reads `<type> <base64> [comment]`; nil for anything else.
    public init?(line: String) {
        let fields = line.split(separator: " ", omittingEmptySubsequences: true)
        // The type goes into a line of `authorized_keys`: nothing that could end or extend it.
        guard fields.count >= 2, fields[0].wholeMatch(of: /[A-Za-z0-9@._+-]{1,64}/) != nil,
              let blob = Data(base64Encoded: String(fields[1])), (4...16 * 1024).contains(blob.count) else { return nil }
        let length = blob.prefix(4).reduce(0) { $0 << 8 | Int($1) }
        guard length > 0, blob.count >= 4 + length,
              String(data: blob.dropFirst(4).prefix(length), encoding: .utf8) == String(fields[0]) else { return nil }
        type = String(fields[0])
        self.blob = blob
    }

    /// `SHA256:` and the blob's digest in unpadded base64, as sshd logs it.
    public var fingerprint: String {
        "SHA256:" + Data(SHA256.hash(data: blob)).base64EncodedString().replacingOccurrences(of: "=", with: "")
    }

    /// The key's size as `ssh-keygen -b` takes it, for the types a decoy can copy.
    var bits: Int? {
        switch type {
        case "ssh-ed25519": return 256
        case "ecdsa-sha2-nistp256": return 256
        case "ecdsa-sha2-nistp384": return 384
        case "ecdsa-sha2-nistp521": return 521
        case "ssh-rsa":
            // The type, the exponent, then the modulus, each length-prefixed.
            var rest = blob[...]
            var field = Data()
            for _ in 0..<3 {
                guard rest.count >= 4 else { return nil }
                let length = rest.prefix(4).reduce(0) { $0 << 8 | Int($1) }
                rest = rest.dropFirst(4)
                guard rest.count >= length else { return nil }
                field = Data(rest.prefix(length))
                rest = rest.dropFirst(length)
            }
            let modulus = field.drop { $0 == 0 }
            guard let first = modulus.first else { return nil }
            return (modulus.count - 1) * 8 + (8 - first.leadingZeroBitCount)
        default: return nil
        }
    }

    /// `<type> <base64>`, as a line's first two fields.
    var line: String { "\(type) \(blob.base64EncodedString())" }

    /// The decoy's line in its account's `authorized_keys` (PLAN.md, The key
    /// line): no forwarding, no pty, no rc, and only `/usr/bin/false`.
    public var decoyLine: String {
        "\(Self.decoyOptions) \(type) \(blob.base64EncodedString())"
    }

    static let decoyOptions = #"restrict,command="/usr/bin/false""#

    /// The key in a decoy line, if the line is exactly one.
    static func inDecoyLine(_ line: String) -> SSHPublicKey? {
        guard line.hasPrefix(decoyOptions + " "), let key = SSHPublicKey(line: String(line.dropFirst(decoyOptions.count + 1))),
              key.decoyLine == line else { return nil }
        return key
    }
}

import BufoKit
import Foundation

// sshd's lines as a test watcher logged them at VERBOSE (PLAN.md, E3 and
// E5), with accounts, paths, addresses, and fingerprints replaced.
enum Fixture {
    static let uuid = "9A2854EC-AB00-3F86-9F2E-FDD69E37A165"
    static let sshd = SSHDIdentity(uuids: [uuid])
    static let decoyFingerprint = "SHA256:S1ft5PYF1DXEoVqfN2HcVhugg4LeD+NQUVSbgD/V6T0"
    static let otherFingerprint = "SHA256:IiloM4w4WdzLS0Eyt+dwlVg1S+hqhxFRUoyAg1gP7A8"
    static let probeFingerprint = "SHA256:l6Su6X7Xdq2B9MH2HUL+PEhWouFqLNe3/aQS0kMCQlU"
    static let decoy = SSHDecoy(id: UUID(uuidString: "00000000-0000-0000-0000-00000000000D")!, account: "builder", uid: 400,
                                fingerprint: decoyFingerprint)

    /// One decoy use, in the order sshd logged it, with the uid each line carried.
    static let decoyUse: [(String, UInt32)] = [
        ("Connection from 192.0.2.10 port 57740 on 192.0.2.1 port 22", 0),
        ("Accepted key ED25519 \(decoyFingerprint) found at /private/var/home/builder/.ssh/authorized_keys:1", 400),
        ("Postponed publickey for builder from 192.0.2.10 port 57740 ssh2 [preauth]", 0),
        ("Accepted key ED25519 \(decoyFingerprint) found at /private/var/home/builder/.ssh/authorized_keys:1", 400),
        ("Failed publickey for builder from 192.0.2.10 port 57740 ssh2: ED25519 \(decoyFingerprint)", 0),
        ("fatal: Access denied for user builder by PAM account configuration [preauth]", 0),
    ]

    /// The owner's own login, which must never trip.
    static let ownerLogin: [(String, UInt32)] = [
        ("Connection from 192.0.2.20 port 57719 on 192.0.2.1 port 22", 0),
        ("Accepted key ED25519 \(otherFingerprint) found at /Users/owner/.ssh/authorized_keys:1", 501),
        ("Postponed publickey for owner from 192.0.2.20 port 57719 ssh2 [preauth]", 0),
        ("Accepted publickey for owner from 192.0.2.20 port 57719 ssh2: ED25519 \(otherFingerprint)", 0),
    ]

    static let start = Date(timeIntervalSince1970: 1_800_000_000)

    static func event(_ message: String, uid: UInt32 = 0, pid: Int32 = 47740, at: Date = start,
                      path: String = "/usr/libexec/sshd-session", imageUUID: String = uuid) -> LogEvent {
        LogEvent(timestamp: at, bootUUID: "B", machTimestamp: UInt64(at.timeIntervalSince(start) * 1_000_000) + 1,
                 processImagePath: path, processImageUUID: imageUUID, processID: pid, userID: uid, eventMessage: message)
    }

    static func events(_ lines: [(String, UInt32)], pid: Int32, at: Date = start) -> [LogEvent] {
        lines.enumerated().map { index, line in event(line.0, uid: line.1, pid: pid, at: at.addingTimeInterval(Double(index) * 0.01)) }
    }
}

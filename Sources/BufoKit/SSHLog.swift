import Foundation

/// One unified-log event from `log stream --style ndjson` (or `log show`),
/// with only the fields the SSH detector reads.
public struct LogEvent: Decodable, Sendable, Equatable {
    public var timestamp: Date
    /// The boot it was logged in (history names it; the stream leaves it
    /// empty), and its Mach time there.
    public var bootUUID: String
    public var machTimestamp: UInt64
    public var processImagePath: String
    public var processImageUUID: String
    public var processID: Int32
    public var userID: UInt32
    public var eventMessage: String

    public init(timestamp: Date, bootUUID: String, machTimestamp: UInt64, processImagePath: String, processImageUUID: String,
                processID: Int32, userID: UInt32, eventMessage: String) {
        self.timestamp = timestamp
        self.bootUUID = bootUUID
        self.machTimestamp = machTimestamp
        self.processImagePath = processImagePath
        self.processImageUUID = processImageUUID
        self.processID = processID
        self.userID = userID
        self.eventMessage = eventMessage
    }

    enum CodingKeys: String, CodingKey {
        case timestamp, bootUUID, machTimestamp, processImagePath, processImageUUID, processID, userID, eventMessage
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let stamp = try container.decode(String.self, forKey: .timestamp)
        guard let date = Self.parseTimestamp(stamp) else {
            throw DecodingError.dataCorruptedError(forKey: .timestamp, in: container, debugDescription: "unreadable timestamp \(stamp)")
        }
        timestamp = date
        bootUUID = try container.decodeIfPresent(String.self, forKey: .bootUUID) ?? ""
        machTimestamp = try container.decode(UInt64.self, forKey: .machTimestamp)
        processImagePath = try container.decode(String.self, forKey: .processImagePath)
        processImageUUID = try container.decode(String.self, forKey: .processImageUUID)
        processID = try container.decode(Int32.self, forKey: .processID)
        userID = try container.decode(UInt32.self, forKey: .userID)
        eventMessage = try container.decodeIfPresent(String.self, forKey: .eventMessage) ?? ""
    }

    /// The log's own form, `2026-10-29 13:22:25.465043-0700`, to the
    /// microsecond: the stream and history read back after a gap are matched
    /// by it (DateFormatter keeps only milliseconds).
    static func parseTimestamp(_ text: String) -> Date? {
        guard let m = text.wholeMatch(of: timestampForm), let micros = Double(m.2) else { return nil }
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ssZ"
        guard let seconds = formatter.date(from: "\(m.1)\(m.3)") else { return nil }
        return seconds.addingTimeInterval(micros / pow(10, Double(m.2.count)))
    }

    nonisolated(unsafe) private static let timestampForm = #/(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})\.(\d{1,9})([+-]\d{4})/#

    /// Decodes one line of ndjson; nil for anything that isn't a whole event
    /// (the stream's header, a truncated line, a line over `maxLine`).
    public static func decode(line: Data) -> LogEvent? {
        guard line.count <= maxLine else { return nil }
        return try? JSONDecoder().decode(LogEvent.self, from: line)
    }

    /// sshd formats every message as `%.500s`; a whole event with its
    /// metadata stays well under this.
    public static let maxLine = 8192
}

/// The sshd binary whose lines count: its path, and the UUIDs of its slices
/// on disk, read at start. A program named `sshd-session` elsewhere logs the
/// same text under its own path, UUID, and user (PLAN.md, E3).
public struct SSHDIdentity: Sendable, Equatable {
    public var path: String
    public var uuids: Set<String>

    /// Where macOS keeps it.
    public static let systemPath = "/usr/libexec/sshd-session"

    public init(path: String = systemPath, uuids: Set<String>) {
        self.path = path
        self.uuids = uuids
    }

    /// Whether an event came from this sshd, running as root or, for the
    /// line it logs while reading an account's `authorized_keys`, as one of
    /// `accountUIDs`.
    public func admits(_ event: LogEvent, accountUIDs: Set<UInt32>) -> Bool {
        event.processImagePath == path && uuids.contains(event.processImageUUID.uppercased())
            && (event.userID == 0 || accountUIDs.contains(event.userID))
    }
}

/// The sshd messages the detector reads, each matched whole. Everything
/// else, and anything that only resembles these, is ignored.
public enum SSHLine: Equatable, Sendable {
    /// `Connection from <address> port <n> on <address> port <n>` (VERBOSE).
    case connection(address: String, port: Int)
    /// `Accepted key <type> SHA256:<fp> found at <file>:<line>`: sshd found
    /// the key in an account's `authorized_keys` (VERBOSE). It names no
    /// account or address; the process does.
    case keyFound(fingerprint: String, file: String)
    /// `Postponed publickey for <user> from <address> port <n> ssh2 [preauth]`.
    case postponed(user: String, address: String, port: Int)
    /// `Accepted publickey for <user> …` or `Failed publickey for <user> …`,
    /// each with the key's fingerprint.
    case publickey(accepted: Bool, user: String, address: String, port: Int, fingerprint: String)
    /// `fatal: Access denied for user <user> by PAM account configuration [preauth]`.
    case deniedByPAM(user: String)
    /// `Invalid user <user> from <address> port <n>`.
    case invalidUser(user: String, address: String, port: Int)

    /// The fingerprint, if the line carries one.
    public var fingerprint: String? {
        switch self {
        case .keyFound(let fingerprint, _), .publickey(_, _, _, _, let fingerprint): fingerprint
        default: nil
        }
    }

    /// The account, if the line names one.
    public var user: String? {
        switch self {
        case .postponed(let user, _, _), .publickey(_, let user, _, _, _), .deniedByPAM(let user), .invalidUser(let user, _, _): user
        default: nil
        }
    }

    /// The source address and port, if the line carries them.
    public var source: (address: String, port: Int)? {
        switch self {
        case .connection(let address, let port), .postponed(_, let address, let port),
             .publickey(_, _, let address, let port, _), .invalidUser(_, let address, let port): (address, port)
        default: nil
        }
    }

    // The account sits between fixed words, so it is read from the right:
    // the last ` from <address> port <n>` ends it. Fingerprints are SHA-256,
    // unpadded base64; key types and addresses have no spaces.
    nonisolated(unsafe) private static let fingerprint = #/SHA256:[A-Za-z0-9+\/]{43}/#
    nonisolated(unsafe) private static let connectionForm = #/^Connection from (\S+) port (\d{1,5}) on \S+ port \d{1,5}$/#
    nonisolated(unsafe) private static let keyFoundForm = #/^Accepted key \S+ (SHA256:[A-Za-z0-9+\/]{43}) found at (.+):\d+$/#
    nonisolated(unsafe) private static let postponedForm = #/^Postponed publickey for (.+) from (\S+) port (\d{1,5}) ssh2 \[preauth\]$/#
    nonisolated(unsafe) private static let publickeyForm =
        #/^(Accepted|Failed) publickey for (.+) from (\S+) port (\d{1,5}) ssh2: \S+ (SHA256:[A-Za-z0-9+\/]{43})$/#
    nonisolated(unsafe) private static let deniedForm = #/^fatal: Access denied for user (.+) by PAM account configuration \[preauth\]$/#
    nonisolated(unsafe) private static let invalidForm = #/^Invalid user (.*) from (\S+) port (\d{1,5})$/#

    public static func parse(_ message: String) -> SSHLine? {
        guard message.utf8.count <= 500 else { return nil }
        if let m = message.wholeMatch(of: publickeyForm), let port = Int(m.4) {
            return .publickey(accepted: m.1 == "Accepted", user: String(m.2), address: String(m.3), port: port, fingerprint: String(m.5))
        }
        if let m = message.wholeMatch(of: keyFoundForm) {
            return .keyFound(fingerprint: String(m.1), file: String(m.2))
        }
        if let m = message.wholeMatch(of: postponedForm), let port = Int(m.3) {
            return .postponed(user: String(m.1), address: String(m.2), port: port)
        }
        if let m = message.wholeMatch(of: connectionForm), let port = Int(m.2) {
            return .connection(address: String(m.1), port: port)
        }
        if let m = message.wholeMatch(of: deniedForm) {
            return .deniedByPAM(user: String(m.1))
        }
        if let m = message.wholeMatch(of: invalidForm), let port = Int(m.3) {
            return .invalidUser(user: String(m.1), address: String(m.2), port: port)
        }
        return nil
    }
}

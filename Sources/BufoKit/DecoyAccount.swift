import Foundation

/// An SSH decoy's account on the detecting watcher (PLAN.md, The SSH-key
/// decoy): a hidden standard account with no password and `/usr/bin/false`
/// for a shell, outside Remote Login's access group, whose root-owned home
/// holds one key line. sshd checks the key and logs it, then PAM refuses
/// the account, so its key trips and never opens a session.
enum DecoyAccount {
    static let homes = "/Users"
    static let shell = "/usr/bin/false"
    static let staff: gid_t = 20

    /// Account names macOS accepts for a local account.
    nonisolated(unsafe) static let name = /[A-Za-z_][A-Za-z0-9_.-]{0,31}/

    static func home(_ account: String) -> String { homes + "/" + account }

    /// The decoy `account` would be for `key`, refused if the name or its
    /// home is taken. Nothing is made yet: the store records it first, so a
    /// retire or uninstall finds whatever a crash leaves.
    static func plan(_ account: String, key: SSHPublicKey) throws -> SSHDecoy {
        guard account.wholeMatch(of: name) != nil else { throw Refusal("that isn't an account name macOS takes") }
        // Looked up in new processes: this one's own lookups cache, and keep an
        // account it just removed (step 6's drill).
        guard System.run("/usr/bin/id", ["-u", "--", account]).status != 0, try record(account) == .absent else {
            throw Refusal("that account already exists")
        }
        guard !System.exists(try rootsAloneDirectory(homes) + "/" + account) else {
            throw Refusal("that account's home already exists")
        }
        return SSHDecoy(id: UUID(), account: account, uid: try freeUID(), fingerprint: key.fingerprint)
    }

    /// Makes the planned account. On failure the caller removes it; errors
    /// never name the account or its home.
    static func create(_ decoy: SSHDecoy, key: SSHPublicKey) throws {
        let user = "/Users/\(decoy.account)", home = try rootsAloneDirectory(homes) + "/" + decoy.account
        guard dscl("-create", user) else { throw Refusal("Directory Services refused a decoy's account") }
        for (attribute, value) in [("UniqueID", "\(decoy.uid)"), ("PrimaryGroupID", "\(staff)"), ("UserShell", shell),
                                   ("NFSHomeDirectory", home), ("RealName", decoy.account), ("Password", "*"),
                                   ("IsHidden", "1")] where !dscl("-create", user, attribute, value) {
            throw Refusal("Directory Services refused a decoy's \(attribute)")
        }
        let keys = home + "/.ssh/authorized_keys"
        guard mkdir(home, 0o755) == 0, mkdir(home + "/.ssh", 0o700) == 0,
              (try? System.write(Data((key.decoyLine + "\n").utf8), to: keys, mode: 0o600)) != nil,
              lchown(keys, decoy.uid, staff) == 0, lchown(home + "/.ssh", decoy.uid, staff) == 0 else {
            throw Refusal("a decoy's home couldn't be made: \(System.lastError)")
        }
        guard !inAccessGroup(decoy.account) else { throw Refusal("Remote Login's access group takes a decoy's account") }
    }

    /// Removes the account and its home, whatever of them exists. A record
    /// under the name with another id is someone's later account: then
    /// nothing is touched.
    static func remove(_ decoy: SSHDecoy) throws {
        switch try record(decoy.account) {
        case .absent: break
        case .present(let uid) where uid == nil || uid == decoy.uid:
            guard dscl("-delete", "/Users/\(decoy.account)") else { throw Refusal("Directory Services won't remove a decoy's account") }
        case .present:
            throw Refusal("a decoy's account name now belongs to another account; nothing was removed")
        }
        let home = try rootsAloneDirectory(homes) + "/" + decoy.account
        guard !System.exists(home) || (try? FileManager.default.removeItem(atPath: home)) != nil else {
            throw Refusal("a decoy's home won't be removed")
        }
    }

    /// What differs from what was armed, in words that name no placement.
    static func problems(_ decoy: SSHDecoy) -> [String] {
        guard let attributes = try? read(decoy.account), attributes["UniqueID"] == "\(decoy.uid)",
              attributes["UserShell"] == shell, attributes["NFSHomeDirectory"] == home(decoy.account) else {
            return ["a decoy's account changed"]
        }
        var problems: [String] = []
        var info = stat(), ssh = stat(), keys = stat()
        let path = home(decoy.account)
        if lstat(path, &info) != 0 || info.st_mode & S_IFMT != S_IFDIR || !rootsAlone(info)
            || lstat(path + "/.ssh", &ssh) != 0 || ssh.st_mode & S_IFMT != S_IFDIR || ssh.st_uid != decoy.uid
            || ssh.st_mode & 0o077 != 0 || lstat(path + "/.ssh/authorized_keys", &keys) != 0 || keys.st_uid != decoy.uid
            || keys.st_mode & 0o7777 != 0o600 {
            problems.append("a decoy's home changed")
        }
        let lines = System.read(path + "/.ssh/authorized_keys").flatMap { String(data: $0, encoding: .utf8) }?
            .split(separator: "\n").map(String.init) ?? []
        if lines.count != 1 || SSHPublicKey.inDecoyLine(lines[0])?.fingerprint != decoy.fingerprint {
            problems.append("a decoy's key line changed")
        }
        if inAccessGroup(decoy.account) { problems.append("Remote Login's access group takes a decoy's account") }
        return problems
    }

    enum Record: Equatable {
        case absent
        /// With its id, if it has one yet.
        case present(uid_t?)
    }

    /// Directory Services' local record named `account`; a lookup that
    /// fails is an error, never an absence.
    static func record(_ account: String) throws -> Record {
        let list = System.run("/usr/bin/dscl", [".", "-list", "/Users"])
        guard list.status == 0, let names = String(data: list.output, encoding: .utf8)?.split(separator: "\n"), !names.isEmpty else {
            throw Refusal("Directory Services didn't list its accounts")
        }
        guard names.contains(where: { $0 == account }) else { return .absent }
        return .present(try read(account)["UniqueID"].flatMap { uid_t($0) })
    }

    /// A local account's standard attributes, each its first value, read
    /// fresh from Directory Services.
    static func read(_ account: String) throws -> [String: String] {
        let read = System.run("/usr/bin/dscl", ["-plist", ".", "-read", "/Users/\(account)"])
        guard read.status == 0,
              let record = (try? PropertyListSerialization.propertyList(from: read.output, format: nil)) as? [String: Any] else {
            throw Refusal("Directory Services didn't read a decoy's account")
        }
        let prefix = "dsAttrTypeStandard:"
        return Dictionary(uniqueKeysWithValues: record.compactMap { key, value in
            guard key.hasPrefix(prefix), let first = (value as? [String])?.first else { return nil }
            return (String(key.dropFirst(prefix.count)), first)
        })
    }

    /// The lowest unused id from where macOS numbers the accounts people use.
    private static func freeUID() throws -> uid_t {
        let listed = String(data: System.run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).output, encoding: .utf8) ?? ""
        let used = Set(listed.split(separator: "\n").compactMap { $0.split(separator: " ").last.flatMap { uid_t($0) } })
        guard !used.isEmpty, let uid = (501..<60_000).first(where: { !used.contains($0) && getpwuid($0) == nil }) else {
            throw Refusal("Directory Services didn't list its accounts")
        }
        return uid_t(uid)
    }

    /// Whether Remote Login's access group, when there is one, takes the account.
    private static func inAccessGroup(_ account: String) -> Bool {
        let answer = System.run("/usr/sbin/dsmemberutil", ["checkmembership", "-U", account, "-G", "com.apple.access_ssh"])
        return String(data: answer.output, encoding: .utf8)?.contains("user is a member") ?? false
    }

    @discardableResult
    private static func dscl(_ arguments: String...) -> Bool {
        System.run("/usr/bin/dscl", ["."] + arguments).status == 0
    }
}

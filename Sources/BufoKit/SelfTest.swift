import Foundation

/// The detector's self-test (PLAN.md, Self-test): a fresh key no account
/// authorizes, offered to sshd on this watcher for a built-in account, whose
/// fingerprint must come back through the log. It proves sshd, its logging,
/// the stream, and the parser, and never names a decoy.
enum SelfTest {
    /// A built-in service account sshd will check a key for and refuse: one
    /// of macOS's own (a leading underscore, an id below 500), with
    /// `/usr/bin/false` and no `authorized_keys`. Chosen at random, once.
    static func chooseAccount() -> String? {
        let listed = String(data: System.run("/usr/bin/dscl", [".", "-list", "/Users", "UniqueID"]).output, encoding: .utf8) ?? ""
        return listed.split(separator: "\n").compactMap { line -> String? in
            let fields = line.split(separator: " ", omittingEmptySubsequences: true)
            guard fields.count == 2, fields[0].hasPrefix("_"), let uid = Int(fields[1]), (1..<500).contains(uid),
                  let entry = getpwnam(String(fields[0]))?.pointee, String(cString: entry.pw_shell) == DecoyAccount.shell,
                  !System.exists(String(cString: entry.pw_dir) + "/.ssh/authorized_keys") else { return nil }
            return String(fields[0])
        }.randomElement()
    }

    /// Makes a key in a fresh directory in `state`; returns the directory, the
    /// key's path, and its fingerprint.
    static func makeKey(in state: String) -> (directory: String, key: String, fingerprint: String)? {
        let directory = state + "/.self-test-" + UUID().uuidString
        guard mkdir(directory, 0o700) == 0 else { return nil }
        let key = directory + "/key"
        guard System.run("/usr/bin/ssh-keygen", ["-q", "-t", "ed25519", "-N", "", "-C", "", "-f", key]).status == 0,
              let line = System.read(key + ".pub").flatMap({ String(data: $0, encoding: .utf8) }),
              let fingerprint = SSHPublicKey(line: line.trimmingCharacters(in: .whitespacesAndNewlines))?.fingerprint else {
            try? FileManager.default.removeItem(atPath: directory)
            return nil
        }
        return (directory, key, fingerprint)
    }

    /// Offers `key` for `account` to sshd here, and nothing else.
    static func offer(_ key: String, account: String) {
        System.run("/usr/bin/ssh", ["-F", "/dev/null", "-i", key, "-l", account, "-o", "IdentitiesOnly=yes",
                                    "-o", "IdentityAgent=none", "-o", "BatchMode=yes", "-o", "PreferredAuthentications=publickey",
                                    "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                                    "-o", "GlobalKnownHostsFile=/dev/null", "-o", "ConnectTimeout=10", "-o", "LogLevel=QUIET",
                                    "127.0.0.1", "true"])
    }
}

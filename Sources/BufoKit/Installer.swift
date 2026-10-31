import Foundation

/// Install, update, and uninstall, as root at the watcher (PLAN.md, Install).
/// Everything goes into directories root alone can change, a new file only
/// where nothing was, and the artifact is copied in before it is checked, so
/// the copy checked is the copy that runs. A step that fails undoes the ones
/// before it.
public enum Installer {
    /// Labels, service names, and file names: no spaces, slashes, or leading dot.
    nonisolated(unsafe) static let name = /[A-Za-z0-9][A-Za-z0-9._-]{0,127}/

    /// Installs the artifact at `artifact` (normally this binary) as
    /// `binary`, with its config beside it, its state in `state`, and a
    /// LaunchDaemon `label` serving `service`; returns once it answers.
    public static func install(artifact: String, binary: String, label: String, service: String,
                               state: String) throws -> InstallConfig {
        try requireRoot()
        for (what, value) in [("label", label), ("service", service)] where value.wholeMatch(of: name) == nil {
            throw Refusal("the \(what) must be letters, digits, dots, dashes, and underscores")
        }
        let binaryName = URL(fileURLWithPath: binary).lastPathComponent
        let stateName = URL(fileURLWithPath: state).lastPathComponent
        guard binary.hasPrefix("/"), state.hasPrefix("/"), binaryName.wholeMatch(of: name) != nil,
              stateName.wholeMatch(of: name) != nil else {
            throw Refusal("the binary and state must be absolute paths whose last part is a plain name")
        }
        guard !launchctl("print", "system/\(label)") else { throw Refusal("launchd already has a job \(label)") }
        let me = try Signature.ofSelf()

        var undo: [() -> Void] = []
        do {
            // The binary's directory: made if missing, under a directory root alone can change.
            let wanted = URL(fileURLWithPath: binary).deletingLastPathComponent().path
            var made: String?
            if !System.exists(wanted) {
                let parent = try rootsAloneDirectory(URL(fileURLWithPath: wanted).deletingLastPathComponent().path)
                let directory = parent + "/" + URL(fileURLWithPath: wanted).lastPathComponent
                guard mkdir(directory, 0o755) == 0 else { throw Refusal("\(directory): \(System.lastError)") }
                made = directory
                undo.append { rmdir(directory) }
            }
            let directory = try rootsAloneDirectory(wanted)
            let binary = directory + "/" + binaryName
            let state = try rootsAloneDirectory(URL(fileURLWithPath: state).deletingLastPathComponent().path) + "/" + stateName
            let config = InstallConfig(label: label, service: service, state: state, madeDirectory: made)
            for path in [binary, binary + ".json", state, config.plist] where System.exists(path) {
                throw Refusal("\(path) already exists")
            }

            guard mkdir(state, 0o700) == 0 else { throw Refusal("\(state): \(System.lastError)") }
            undo.append { try? FileManager.default.removeItem(atPath: state) }
            try System.write(Data(UUID().uuidString.utf8), to: state + "/watcher", mode: 0o600)

            let staged = try stage(artifact, in: directory, as: binaryName)
            undo.append { unlink(staged) }
            // The copy is this very build, not another of the same team.
            guard try Signature.check(staged, requirement: me.requirement) == me else {
                throw Refusal("\(artifact) changed while it was being installed")
            }
            guard renamex_np(staged, binary, UInt32(RENAME_EXCL)) == 0 else { throw Refusal("\(binary): \(System.lastError)") }
            undo.append { unlink(binary) }
            try System.write(try JSONEncoder().encode(config), to: binary + ".json", mode: 0o644)
            undo.append { unlink(binary + ".json") }

            try System.write(plist(config, binary: binary, signature: me), to: config.plist, mode: 0o644)
            undo.append { unlink(config.plist) }
            guard launchctl("bootstrap", "system", config.plist) else { throw Refusal("launchd refused the job") }
            undo.append { _ = launchctl("bootout", "system/\(label)") }
            try awaitAnswer(config, requirement: me.requirement, version: me.version)
            return config
        } catch {
            for step in undo.reversed() { step() }
            throw error
        }
    }

    /// Replaces the installed binary with `artifact`, which must be this
    /// build's team and identifier and a newer version; if the new one
    /// doesn't answer, the old one is put back.
    public static func update(artifact: String, binary: String, config: InstallConfig) throws -> Signature {
        try requireRoot()
        let me = try Signature.ofSelf()
        let directory = try rootsAloneDirectory(URL(fileURLWithPath: binary).deletingLastPathComponent().path)
        let name = URL(fileURLWithPath: binary).lastPathComponent
        let binary = directory + "/" + name
        let staged = try stage(artifact, in: directory, as: name)
        defer { unlink(staged) }
        let new = try Signature.check(staged, requirement: me.requirement)
        guard new.version > me.version else { throw Refusal("version \(new.version) isn't newer than \(me.version)") }
        let old = directory + "/." + name + "." + UUID().uuidString
        guard link(binary, old) == 0 else { throw Refusal("\(binary): \(System.lastError)") }
        guard rename(staged, binary) == 0 else {
            unlink(old)
            throw Refusal("\(binary): \(System.lastError)")
        }
        do {
            launchctl("kickstart", "-k", "system/\(config.label)")
            try awaitAnswer(config, requirement: me.requirement, version: new.version)
            unlink(old)
            return new
        } catch {
            // The old binary stays aside until it is back in place.
            guard rename(old, binary) == 0 else { throw Refusal("\(error); the old binary is at \(old)") }
            launchctl("kickstart", "-k", "system/\(config.label)")
            throw error
        }
    }

    /// Removes the job, its decoys' accounts, sshd's file,
    /// and every file install made; returns the files it removed and how many
    /// decoys it retired, never which. It stops at the first thing it can't
    /// remove, keeping the binary and then its config to the last so
    /// uninstall can run again.
    public static func uninstall(binary: String, config: InstallConfig) throws -> (files: [String], decoys: Int) {
        try requireRoot()
        let directory = try rootsAloneDirectory(URL(fileURLWithPath: binary).deletingLastPathComponent().path)
        let binary = directory + "/" + URL(fileURLWithPath: binary).lastPathComponent
        guard launchctl("bootout", "system/\(config.label)") || !launchctl("print", "system/\(config.label)") else {
            throw Refusal("launchd won't let go of \(config.label)")
        }
        var removed: [String] = []
        func gone(_ path: String, _ result: Int32) throws {
            if result == 0 { removed.append(path) } else if errno != ENOENT {
                throw Refusal("\(path): \(System.lastError); removed so far: \(removed.joined(separator: ", "))")
            }
        }
        try gone(config.plist, unlink(config.plist))
        var decoys = 0
        if System.exists(config.state) {
            let store = try Store.load(config.state, watcher: UUID())
            for decoy in store.decoys {
                try DecoyAccount.remove(decoy)
                decoys += 1
            }
            try SSHDConfig.remove(file: store.sshdFile)
            if let file = store.sshdFile { removed.append(SSHDConfig.directory + "/" + file) }
            _ = try rootsAloneDirectory(config.state)
            try FileManager.default.removeItem(atPath: config.state)
            removed.append(config.state)
        }
        try gone(binary, unlink(binary))
        try gone(binary + ".json", unlink(binary + ".json"))
        // Left in place when something else has since moved in.
        if let made = config.madeDirectory, rmdir(made) == 0 { removed.append(made) }
        return (removed, decoys)
    }

    // MARK: -

    static func plist(_ config: InstallConfig, binary: String, signature: Signature) throws -> Data {
        try PropertyListSerialization.data(fromPropertyList: [
            "Label": config.label,
            "ProgramArguments": [binary, "daemon"],
            "MachServices": [config.service: true],
            "RunAtLoad": true,
            "KeepAlive": true,
            // launchd runs nothing at this path but this team's build of this identifier.
            "SpawnConstraint": ["team-identifier": signature.team, "signing-identifier": signature.identifier],
        ] as [String: Any], format: .xml, options: 0)
    }

    static func requireRoot() throws {
        guard geteuid() == 0 else { throw Refusal("this takes root at the watcher: run it with sudo") }
    }

    /// Copies `artifact` to a fresh hidden name in `directory`.
    static func stage(_ artifact: String, in directory: String, as name: String) throws -> String {
        let data: Data
        do { data = try Data(contentsOf: URL(fileURLWithPath: artifact)) } catch { throw Refusal("\(artifact) can't be read") }
        let staged = directory + "/." + name + "." + UUID().uuidString
        try System.write(data, to: staged, mode: 0o755)
        return staged
    }

    static func awaitAnswer(_ config: InstallConfig, requirement: String, version: Int) throws {
        for _ in 0..<20 {
            if let status = try? Service.status(config.service, requirement: requirement, timeout: 1), status.version == version {
                return
            }
            Thread.sleep(forTimeInterval: 0.5)
        }
        throw Refusal("the daemon didn't answer")
    }

    @discardableResult
    static func launchctl(_ arguments: String...) -> Bool {
        System.run("/bin/launchctl", arguments).status == 0
    }
}

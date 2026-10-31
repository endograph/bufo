import Foundation

/// What the SSH decoy needs of sshd on the detecting watcher (PLAN.md, The
/// SSH-key decoy): one file in `sshd_config.d` holding only `LogLevel
/// VERBOSE`, named and ordered like its neighbours, which names no decoy.
enum SSHDConfig {
    static let directory = "/etc/ssh/sshd_config.d"
    static let contents = Data("LogLevel VERBOSE\n".utf8)

    /// A name for the file among `neighbours` (name and contents): a
    /// numbered prefix as wide as theirs, a number below every neighbour's
    /// and so before any that sets `LogLevel` (sshd takes the first value it
    /// reads), and `word`. Nil when there's no room before them.
    static func fileName(among neighbours: [String: String], word: String) -> String? {
        let numbered = neighbours.keys.compactMap { name -> (Substring, Int)? in
            guard let m = name.prefixMatch(of: /(\d+)-/), let n = Int(m.1) else { return nil }
            return (m.1, n)
        }
        let width = numbered.first?.0.count ?? 3
        let limit = numbered.map(\.1).min() ?? Int(pow(10, Double(width)))
        guard limit > 1 else { return nil }
        let number = String(Int.random(in: 1..<limit))
        let name = String(repeating: "0", count: max(0, width - number.count)) + number + "-" + word + ".conf"
        let setters = neighbours.filter { $0.value.split(separator: "\n").contains { $0.wholeMatch(of: /\s*(?i:loglevel)\s.*/) != nil } }
        guard neighbours[name] == nil, setters.keys.allSatisfy({ name < $0 }) else { return nil }
        return name
    }

    /// A name for Bufo's file among those in the directory now.
    static func chooseName(word: String) throws -> String {
        let directory = try rootsAloneDirectory(directory)
        var neighbours: [String: String] = [:]
        for name in (try? FileManager.default.contentsOfDirectory(atPath: directory)) ?? [] {
            neighbours[name] = System.read(directory + "/" + name).flatMap { String(data: $0, encoding: .utf8) } ?? ""
        }
        guard let name = fileName(among: neighbours, word: word) else {
            throw Refusal("there's no room in \(directory) for a file sshd reads first")
        }
        return name
    }

    /// Writes the file if it is missing, then refuses unless sshd reads
    /// `LogLevel VERBOSE` and allows no tunnels; the caller removes it.
    static func set(file: String) throws {
        let path = try rootsAloneDirectory(directory) + "/" + file
        if !System.exists(path) { try System.write(contents, to: path, mode: 0o644) }
        if let problem = problems(file: file).first { throw Refusal(problem) }
    }

    /// Removes the file; one already gone counts as removed.
    static func remove(file: String?) throws {
        if let file, unlink(directory + "/" + file) != 0, errno != ENOENT {
            throw Refusal("\(directory)/\(file): \(System.lastError)")
        }
    }

    /// What differs from what was set, in words that name no placement.
    static func problems(file: String) -> [String] {
        var problems = effectiveProblems()
        if System.read(directory + "/" + file) != contents { problems.append("Bufo's sshd file changed") }
        return problems
    }

    /// sshd's effective config (`sshd -T`) as the decoy needs it.
    static func effectiveProblems() -> [String] {
        let run = System.run("/usr/sbin/sshd", ["-T"])
        let settings = String(data: run.output, encoding: .utf8)?.split(separator: "\n").reduce(into: [String: String]()) {
            let pair = $1.split(separator: " ", maxSplits: 1)
            if pair.count == 2 { $0[pair[0].lowercased()] = String(pair[1]) }
        } ?? [:]
        guard run.status == 0, !settings.isEmpty else { return ["sshd's config doesn't read"] }
        var problems: [String] = []
        if settings["loglevel"] != "VERBOSE" { problems.append("sshd doesn't log at VERBOSE") }
        if settings["permittunnel"] != "no" { problems.append("sshd allows tunnels") }
        return problems
    }
}

import CryptoKit
import Foundation
import Network

/// An SSH decoy planted on a bait laptop from this watcher (PLAN.md, The
/// SSH-key decoy, On the bait laptop): placement data, kept in the store
/// and nowhere else. The private key is never kept past its verification.
public struct Bait: Codable, Sendable, Equatable {
    public var id: UUID
    /// `[user@]host`, as the owner gave it.
    public var destination: String
    /// The peer that detects it, or nil when this watcher does.
    public var detector: UUID?
    public var account: String
    /// `<type> <base64>`.
    public var key: String
    public var keyFile: String
    public var keySum: String
    public var pubFile: String?
    public var pubSum: String?
    /// Exactly what went into `~/.ssh/config`, found and taken out whole.
    public var entry: String
    public var patterns: [String]
    /// What `ssh -G` should resolve for the first pattern.
    public var hostName: String
    public var identityFile: String
    /// The name the entry looks the detector's host key up by.
    public var lookup: String
    public var knownLine: String?
    public var planted: Date?
}

/// The detecting watcher as a bait laptop could name it: its tailnet
/// address, its name there if the address has one, and sshd's host key.
public struct DetectorNames: Codable, Sendable, Equatable {
    public var address: String
    public var dns: String?
    /// `<type> <base64>`.
    public var hostKey: String?

    var short: String? { dns.flatMap { $0.split(separator: ".").first.map(String.init) } }
    var all: Set<String> { Set([address, dns, short].compactMap { $0?.lowercased() }) }

    /// The detector's name in the form `value` names its own machine: an
    /// address, a dotted name, or a bare one.
    func form(of value: String) -> String? {
        let bare = value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        if IPv4Address(bare) != nil || IPv6Address(bare) != nil { return address }
        return bare.contains(".") ? dns : short
    }
}

/// One file change on the bait laptop, checked before any is made and safe
/// to repeat: each is skipped when already done.
public enum BaitChange: Codable, Sendable, Equatable {
    /// A new file where none was, with its mode and modification time.
    case create(name: String, content: Data, mode: Int, modified: Int)
    /// A file replaced if it's still what the survey saw; its mode and time kept.
    case replace(name: String, expect: String, content: Data)
    /// A line added if the file is still what the survey saw; its time kept.
    case append(name: String, expect: String, line: String)
    /// A file removed if it's still what was written.
    case delete(name: String, expect: String)
    /// A line taken out; its time kept.
    case dropLine(name: String, line: String)
}

func sha256(_ data: Data) -> String { SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined() }

/// Makes an SSH decoy from a bait laptop's survey (PLAN.md, Imitation
/// without lists): every choice copies something already there, or the
/// randomness this watcher makes, and where there's nothing to copy it
/// refuses. Refusals describe the laptop, never the decoy.
enum BaitPlanner {
    struct Plan {
        var bait: Bait
        var writes: [BaitChange]
    }

    /// Makes a key pair: `ssh-keygen` type and bits, the private key format
    /// (`OpenSSH`, `PEM`, or `PKCS8`), and the comment; returns the private
    /// key file and the `.pub` file.
    typealias KeyMaker = (_ type: String, _ bits: Int, _ format: String, _ comment: String) throws
        -> (privateKey: Data, publicFile: Data)

    /// Options a decoy's entry copies as they are; an entry with any other
    /// (a proxy, a forward, a command) isn't one to copy.
    static let copied: Set<String> = [
        "host", "hostname", "user", "port", "identityfile", "identitiesonly", "hostkeyalias", "addkeystoagent",
        "usekeychain", "stricthostkeychecking", "serveraliveinterval", "serveralivecountmax", "compression",
        "connecttimeout", "loglevel", "forwardagent", "forwardx11", "preferredauthentications", "pubkeyauthentication",
        "passwordauthentication", "kbdinteractiveauthentication", "controlmaster", "controlpath", "controlpersist",
        "requesttty", "tcpkeepalive", "updatehostkeys", "visualhostkey", "hashknownhosts", "ipqos", "sendenv",
        "checkhostip", "addressfamily", "batchmode", "userknownhostsfile",
    ]

    static func plan(_ survey: BaitSurvey, detector: DetectorNames, detectorPeer: UUID?, destination: String,
                     makeKey: KeyMaker, random: inout some RandomNumberGenerator) throws -> Plan {
        guard let configText = survey.config, let configFile = survey.files["config"], configFile.regular,
              let configSum = configFile.sum else {
            throw Refusal("the bait laptop has no ~/.ssh/config to copy an entry from")
        }
        let keys = survey.keys.filter { survey.files[$0.name]?.regular == true }
        guard keys.count >= 2 else { throw Refusal("the bait laptop has fewer than two private keys to copy from") }
        guard keys.contains(where: { !$0.passphrase }) else {
            throw Refusal("every private key on the bait laptop has a passphrase, and a decoy can't")
        }
        let resolved = survey.resolved
        let identities = survey.identities + resolved.values.flatMap { $0["identityfile", default: []] }
        guard !identities.contains(where: perDestination) else {
            throw Refusal("an IdentityFile on the bait laptop names keys by destination, so it could offer a decoy")
        }

        // What the laptop's names are made of: the hosts and users it reaches.
        let config = SSHConfigText(configText)
        var hostWords = Set<String>(), userWords = Set<String>()
        for (name, options) in resolved {
            if !isPattern(name) { hostWords.insert(firstLabel(name)) }
            options["hostname", default: []].forEach { hostWords.insert(firstLabel($0)) }
            options["user", default: []].forEach { userWords.insert($0.lowercased()) }
        }
        let toDetector = resolved.values.filter { options in
            (options["hostname", default: []] + options["hostkeyalias", default: []]).contains { detector.all.contains($0.lowercased()) }
        }
        let taken = !toDetector.isEmpty

        // The account: a user the laptop already names, and doesn't use on the detector.
        let used = Set(toDetector.flatMap { $0["user", default: []] }.map { $0.lowercased() })
        let commentUsers = survey.pubs.values.compactMap { line -> String? in
            let comment = comment(of: line)
            return comment.firstIndex(of: "@").map { String(comment[..<$0]).lowercased() }
        }
        let candidates = userWords.union(commentUsers).union(survey.accounts.map { $0.lowercased() })
            .subtracting(used).subtracting(hostWords).subtracting([survey.user.lowercased(), "root"])
            .filter { $0.wholeMatch(of: /[a-z][a-z0-9_-]{1,15}/) != nil }
            .sorted()
        guard let account = candidates.randomElement(using: &random) else {
            throw Refusal("the bait laptop names no user a decoy's account could copy")
        }

        // The entry: a real one, its options copied in order.
        let templates = config.blocks.filter { block in
            let options = config.options(block)
            return block.host && !block.patterns.isEmpty && !block.patterns.contains(where: isPattern)
                && options.contains { $0.keyword == "user" } && options.allSatisfy { copied.contains($0.keyword ?? "") }
        }
        guard let template = templates.randomElement(using: &random) else {
            throw Refusal("no Host entry on the bait laptop names a user and could be copied")
        }
        let options = config.options(template)
        guard options.contains(where: { $0.keyword == "port" }) || resolved[template.patterns[0]]?["port"]?.first == "22" else {
            throw Refusal("the bait laptop's entries reach SSH on another port than the detector's")
        }

        var patterns: [String] = []
        if !taken {
            // The detector is new to the laptop: named as the template names its machine.
            for pattern in template.patterns {
                guard let name = detector.form(of: pattern) else {
                    throw Refusal("the detecting watcher has no name in the form the bait laptop uses")
                }
                if !patterns.contains(where: { $0.lowercased() == name.lowercased() }) { patterns.append(name) }
            }
        } else {
            // The laptop reaches the detector already: a second account there,
            // named with the separator the laptop's own names use most.
            let separators = (Array(resolved.keys) + Array(survey.files.keys)).flatMap { $0.filter { $0 == "-" || $0 == "_" } }
            let counts = Dictionary(grouping: separators, by: { $0 }).mapValues(\.count)
            guard let separator = counts.sorted(by: { ($0.value, $1.key) > ($1.value, $0.key) }).first?.key,
                  let short = detector.short else {
                throw Refusal("the bait laptop's names give nothing to copy a second name for the same machine from")
            }
            patterns = [short + String(separator) + account]
        }
        let existing = Set(config.blocks.flatMap(\.patterns).map { $0.lowercased() }).union(resolved.keys.map { $0.lowercased() })
        guard let alias = patterns.first, !patterns.contains(where: { existing.contains($0.lowercased()) }) else {
            throw Refusal("the bait laptop already has an entry by the name a decoy's would take")
        }

        // The key: a real one's type, size, format, and comment, under its name
        // with the host or user it names changed to the decoy's.
        func replacement(_ word: String) -> String? {
            if hostWords.contains(word) { return taken ? account : detector.short }
            if userWords.contains(word) { return account }
            return nil
        }
        var model: (key: BaitSurvey.Key, type: String, bits: Int, name: String, comment: String)?
        for key in keys.shuffled(using: &random) where !key.passphrase && !BaitSurvey.defaultNames.contains(key.name) {
            guard let line = key.publicLine, let publicKey = SSHPublicKey(line: line), let type = keygenType(publicKey.type),
                  let bits = publicKey.bits else { continue }
            var changes: [String: String] = [:]
            for word in words(key.name) {
                if let new = replacement(word.lowercased()) { changes[word] = new }
            }
            let name = rebuild(key.name, changes)
            guard !changes.isEmpty, survey.files[name] == nil, survey.files[name + ".pub"] == nil,
                  !BaitSurvey.defaultNames.contains(name) else { continue }
            let comment = comment(of: survey.pubs[key.name + ".pub"] ?? line)
            model = (key, type, bits, name, rebuild(comment, changes))
            break
        }
        guard let model else { throw Refusal("no key on the bait laptop has a name a decoy's could be formed like") }
        let decoyPath = survey.home + "/.ssh/" + model.name
        guard !identities.contains(where: { expand($0, home: survey.home) == decoyPath }) else {
            throw Refusal("an IdentityFile on the bait laptop would offer a decoy")
        }
        let format = model.key.header.contains("OPENSSH") ? "OpenSSH" : model.key.header.contains("BEGIN PRIVATE KEY") ? "PKCS8" : "PEM"
        let made = try makeKey(model.type, model.bits, format, model.comment)
        guard String(decoding: made.privateKey.prefix(80), as: UTF8.self).split(separator: "\n").first.map(String.init) == model.key.header,
              let decoyKey = SSHPublicKey(line: String(decoding: made.publicFile, as: UTF8.self)) else {
            throw Refusal("a decoy key couldn't be made in the format the bait laptop's keys use")
        }

        // The entry's lines, in the template's indentation, separator, and keyword case.
        let first = options.first { $0.keyword != "host" }
        let indent = first.map { String($0.prefix.prefix { $0 == " " || $0 == "\t" }) } ?? "  "
        let separator = first.map { String($0.prefix.drop { $0 == " " || $0 == "\t" }.drop { !" \t=".contains($0) }) } ?? " "
        let lowercase = options.allSatisfy { written($0) == written($0).lowercased() }
        func added(_ keyword: String, _ value: String) -> String { indent + (lowercase ? keyword.lowercased() : keyword) + separator + value }
        func named(_ value: String) throws -> String {
            guard let name = detector.form(of: value) else {
                throw Refusal("the detecting watcher has no name in the form the bait laptop uses")
            }
            return name
        }
        var lines: [String] = [], hostName = alias, identityFile: String?
        for line in options {
            switch line.keyword {
            case "host":
                let gap = line.value.firstMatch(of: /[ \t]+/).map { String($0.output) } ?? " "
                lines.append(line.prefix + patterns.joined(separator: gap))
                if taken, !options.contains(where: { $0.keyword == "hostname" }) {
                    hostName = try named(template.patterns[0])
                    lines.append(added("HostName", hostName))
                }
            case "hostname":
                hostName = try named(line.value)
                lines.append(line.prefix + hostName)
            case "hostkeyalias": lines.append(line.prefix + (try named(line.value)))
            case "user": lines.append(line.prefix + account)
            case "port": lines.append(line.prefix + "22")
            case "identityfile":
                guard identityFile == nil else { continue }
                identityFile = renamed(line.value, to: model.name)
                lines.append(line.prefix + identityFile!)
            default: lines.append(line.prefix + line.value)
            }
        }
        if identityFile == nil {
            identityFile = renamed(config.lines.first { $0.keyword == "identityfile" }?.value ?? "~/.ssh/x", to: model.name)
            lines.append(added("IdentityFile", identityFile!))
        }
        let insertion = config.insertion(after: template, entry: lines)

        // known_hosts: a line for the detector when the template's machine has
        // one there and the detector, under the name the entry looks it up by, hasn't.
        let lookup = lines.map(SSHConfigText.line).first { $0.keyword == "hostkeyalias" }?.value ?? hostName
        var knownLine: String?
        if survey.files["known_hosts"]?.regular == true, !survey.known.contains(lookup),
           let model = resolved[template.patterns[0]], let modelLookup = (model["hostkeyalias"] ?? model["hostname"])?.first,
           survey.known.contains(modelLookup) {
            guard let hostKey = detector.hostKey else { throw Refusal("the detecting watcher's host key couldn't be read") }
            let hashed = survey.knownHashed * 2 > survey.knownLines
            knownLine = (hashed ? hashedName(lookup, random: &random) : lookup) + " " + hostKey
        }

        // Files: the model's modes, a time among the real keys', the .pub as far behind as the model's.
        let times = keys.compactMap { survey.files[$0.name]?.modified }
        let modified = Int.random(in: (times.min() ?? 0)...(times.max() ?? 0), using: &random)
        let keyFile = survey.files[model.key.name]!
        var writes: [BaitChange] = [.create(name: model.name, content: made.privateKey, mode: keyFile.mode, modified: modified)]
        var pubFile: String?
        if let modelPub = survey.files[model.key.name + ".pub"], modelPub.regular {
            pubFile = model.name + ".pub"
            writes.append(.create(name: model.name + ".pub", content: made.publicFile, mode: modelPub.mode,
                                  modified: modified + modelPub.modified - keyFile.modified))
        }
        writes.append(.replace(name: "config", expect: configSum, content: Data(config.inserting(insertion, after: template).utf8)))
        if let knownLine, let sum = survey.files["known_hosts"]?.sum {
            writes.append(.append(name: "known_hosts", expect: sum, line: knownLine))
        }
        let bait = Bait(id: UUID(), destination: destination, detector: detectorPeer, account: account, key: decoyKey.line,
                        keyFile: model.name, keySum: sha256(made.privateKey), pubFile: pubFile,
                        pubSum: pubFile.map { _ in sha256(made.publicFile) }, entry: insertion, patterns: patterns,
                        hostName: hostName, identityFile: identityFile!, lookup: lookup, knownLine: knownLine, planted: nil)
        return Plan(bait: bait, writes: writes)
    }

    /// What's wrong with `bait` as a later survey sees it, in words that
    /// name no placement; nil when it's as written and nothing else on the
    /// laptop would offer it.
    static func problem(_ bait: Bait, _ survey: BaitSurvey) -> String? {
        guard survey.files[bait.keyFile]?.sum == bait.keySum, bait.pubFile.map({ survey.files[$0]?.sum == bait.pubSum }) ?? true,
              survey.config?.contains(bait.entry) == true else {
            return "the bait didn't land on the bait laptop as written"
        }
        let path = survey.home + "/.ssh/" + bait.keyFile
        guard let own = survey.resolved[bait.patterns[0]], own["hostname"]?.first == bait.hostName,
              own["user"]?.first == bait.account, own["port"]?.first == "22",
              own["identityfile", default: []].contains(where: { expand($0, home: survey.home) == path }) else {
            return "the bait's entry doesn't resolve on the bait laptop as written"
        }
        let patterns = Set(bait.patterns.map { $0.lowercased() })
        let others = survey.resolved.filter { !patterns.contains($0.key.lowercased()) }.values.flatMap { $0["identityfile", default: []] }
        if (others + survey.identities).contains(where: perDestination) { return "an IdentityFile on the bait laptop names keys by destination" }
        // The decoy's own entry names it once; any other mention offers it elsewhere.
        if others.contains(where: { expand($0, home: survey.home) == path })
            || survey.identities.filter({ expand($0, home: survey.home) == path }).count > 1 {
            return "another entry on the bait laptop would offer the decoy"
        }
        let key = SSHPublicKey(line: bait.key)
        if survey.agent.contains(where: { SSHPublicKey(line: $0) == key }) { return "an agent on the bait laptop holds the decoy" }
        return nil
    }

    /// The changes that take `bait` off the laptop as a survey now sees it:
    /// only what is still as written.
    static func removal(_ bait: Bait, _ survey: BaitSurvey) throws -> [BaitChange] {
        var changes: [BaitChange] = []
        if let config = survey.config, let sum = survey.files["config"]?.sum, config.contains(bait.entry) {
            guard let removed = SSHConfigText.removing(bait.entry, from: config) else {
                throw Refusal("the bait laptop's config holds the bait's entry more than once")
            }
            changes.append(.replace(name: "config", expect: sum, content: Data(removed.utf8)))
        }
        // The detector's known_hosts line stays while another entry looks it up by the same name.
        let patterns = Set(bait.patterns.map { $0.lowercased() })
        let stillUsed = survey.resolved.contains { name, options in
            !patterns.contains(name.lowercased()) && (options["hostkeyalias"] ?? options["hostname"])?.first?.lowercased() == bait.lookup.lowercased()
        }
        if let line = bait.knownLine, survey.files["known_hosts"]?.regular == true, !stillUsed {
            changes.append(.dropLine(name: "known_hosts", line: line))
        }
        if survey.files[bait.keyFile]?.sum == bait.keySum { changes.append(.delete(name: bait.keyFile, expect: bait.keySum)) }
        if let pub = bait.pubFile, let sum = bait.pubSum, survey.files[pub]?.sum == sum { changes.append(.delete(name: pub, expect: sum)) }
        return changes
    }

    /// An IdentityFile whose path depends on where ssh connects.
    static func perDestination(_ value: String) -> Bool {
        value.matches(of: /%(.)/).contains { !["d", "u", "%"].contains($0.output.1) }
    }

    static func isPattern(_ name: String) -> Bool { name.contains { "*?!".contains($0) } }

    static func firstLabel(_ name: String) -> String { String(name.split(separator: ".").first ?? "").lowercased() }

    /// The words of a name, between its `-`, `_`, and `.`.
    static func words(_ name: String) -> [String] { name.split(whereSeparator: { "-_.".contains($0) }).map(String.init) }

    /// `text` with each whole word in `changes` replaced.
    static func rebuild(_ text: String, _ changes: [String: String]) -> String {
        guard !changes.isEmpty else { return text }
        var out = "", word = ""
        for character in text + " " {
            if character.isLetter || character.isNumber {
                word.append(character)
            } else {
                out += changes[word] ?? word
                out.append(character)
                word = ""
            }
        }
        return String(out.dropLast())
    }

    /// A public key line's comment: everything after its second field.
    static func comment(of line: String) -> String {
        let fields = line.split(separator: " ", maxSplits: 2)
        return fields.count == 3 ? String(fields[2]).trimmingCharacters(in: .whitespacesAndNewlines) : ""
    }

    /// An IdentityFile value as a path: unquoted, `~` and `%d` as home.
    static func expand(_ value: String, home: String) -> String {
        var path = value.trimmingCharacters(in: .whitespaces).trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        for prefix in ["~/", "%d/"] where path.hasPrefix(prefix) { path = home + "/" + path.dropFirst(prefix.count) }
        if !path.hasPrefix("/") { path = home + "/" + path }
        path = path.replacingOccurrences(of: "%u", with: URL(fileURLWithPath: home).lastPathComponent)
        return URL(fileURLWithPath: path).standardized.path
    }

    /// `value`, an IdentityFile path as written, naming `file` instead, in the same form.
    static func renamed(_ value: String, to file: String) -> String {
        let quoted = value.hasPrefix("\"")
        let path = value.trimmingCharacters(in: CharacterSet(charactersIn: "\""))
        let directory = path.contains("/") ? String(path[...path.lastIndex(of: "/")!]) : ""
        return quoted ? "\"\(directory)\(file)\"" : directory + file
    }

    /// `ssh-keygen -t` for a key type a decoy can be made as.
    static func keygenType(_ type: String) -> String? {
        switch type {
        case "ssh-ed25519": "ed25519"
        case "ssh-rsa": "rsa"
        case "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521": "ecdsa"
        default: nil
        }
    }

    /// `known_hosts`' hashed form of `name`: a random salt and HMAC-SHA1.
    static func hashedName(_ name: String, random: inout some RandomNumberGenerator) -> String {
        let salt = Data((0..<20).map { _ in UInt8.random(in: 0...255, using: &random) })
        let mac = HMAC<Insecure.SHA1>.authenticationCode(for: Data(name.utf8), using: SymmetricKey(data: salt))
        return "|1|\(salt.base64EncodedString())|\(Data(mac).base64EncodedString())"
    }

    /// A line's keyword as written.
    static func written(_ line: SSHConfigText.Line) -> String {
        String(line.prefix.drop { $0 == " " || $0 == "\t" }.prefix { !" \t=".contains($0) })
    }
}

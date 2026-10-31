@testable import BufoKit
import Foundation
import Testing

/// A seeded generator, so a plan is the same each run.
struct Seeded: RandomNumberGenerator {
    var state: UInt64
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

struct SSHConfigTextTests {
    @Test func anEntryGoesInAndComesOutLeavingEveryByte() throws {
        for original in ["Host a\n  User x\n\nHost b\n  User y\n", "Host a\n  User x", "# top\nHost a\n\tUser x\n\n\n# b\nHost b\n  User y\n"] {
            let config = SSHConfigText(original)
            #expect(config.text == original)
            for block in config.blocks {
                let insertion = config.insertion(after: block, entry: ["Host c", "  User z"])
                let planted = config.inserting(insertion, after: block)
                #expect(planted.contains("Host c\n  User z"))
                #expect(SSHConfigText.removing(insertion, from: planted) == original)
                #expect(SSHConfigText.removing(insertion, from: original) == original)
            }
        }
    }

    @Test func linesKeepWhatComesBeforeTheirValue() {
        let line = SSHConfigText.line("\tIdentityFile = \"~/.ssh/k\"  ")
        #expect(line.keyword == "identityfile")
        #expect(line.value == "\"~/.ssh/k\"")
        #expect(line.prefix == "\tIdentityFile = ")
        #expect(SSHConfigText.line("  # Host x").keyword == nil)
    }
}

/// The survey and write scripts, run with /bin/sh against a made-up `~/.ssh`.
struct PlantingTests {
    let home: String
    let detector: DetectorNames
    let original = """
        # Personal
        Host github.com
          User git
          IdentityFile ~/.ssh/github_ed25519
          IdentitiesOnly yes

        Host devbox devbox.example.ts.net
          HostName devbox.example.ts.net
          User sam

        Host *
          AddKeysToAgent yes

        """

    init() throws {
        home = FileManager.default.temporaryDirectory.appendingPathComponent("bait-" + UUID().uuidString).path
        let ssh = home + "/.ssh"
        try FileManager.default.createDirectory(atPath: ssh, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        try Self.keygen(["-t", "ed25519", "-N", "a passphrase", "-C", "owner@laptop", "-f", ssh + "/id_ed25519"])
        try Self.keygen(["-t", "ed25519", "-N", "", "-C", "owner@laptop", "-f", ssh + "/github_ed25519"])
        try Data(original.utf8).write(to: URL(fileURLWithPath: ssh + "/config"))
        let devbox = try Self.publicKey()
        try Data("github.com \(try Self.publicKey())\ndevbox.example.ts.net \(devbox)\n".utf8).write(to: URL(fileURLWithPath: ssh + "/known_hosts"))
        detector = DetectorNames(address: "100.64.0.9", dns: "vault.example.ts.net", hostKey: try Self.publicKey())
    }

    static func keygen(_ arguments: [String]) throws {
        guard System.run("/usr/bin/ssh-keygen", ["-q"] + arguments).status == 0 else { throw Refusal("ssh-keygen failed") }
    }

    static func publicKey() throws -> String {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try keygen(["-t", "ed25519", "-N", "", "-f", directory + "/k"])
        return SSHPublicKey(line: try String(contentsOfFile: directory + "/k.pub", encoding: .utf8))!.line
    }

    static func makeKey(type: String, bits: Int, format: String, comment: String) throws -> (privateKey: Data, publicFile: Data) {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try keygen(["-t", type, "-b", "\(bits)", "-N", "", "-C", comment, "-f", directory + "/k"] + (format == "OpenSSH" ? [] : ["-m", format]))
        return (try Data(contentsOf: URL(fileURLWithPath: directory + "/k")), try Data(contentsOf: URL(fileURLWithPath: directory + "/k.pub")))
    }

    func run(_ script: String) throws -> (Data, Int32) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/bin/sh")
        process.arguments = ["-s"]
        process.environment = ["HOME": home, "PATH": "/usr/bin:/bin"]
        let input = Pipe(), output = Pipe()
        process.standardInput = input
        process.standardOutput = output
        try process.run()
        try input.fileHandleForWriting.write(contentsOf: Data(script.utf8))
        try input.fileHandleForWriting.close()
        let data = output.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        return (data, process.terminationStatus)
    }

    func survey() throws -> BaitSurvey {
        let script = BaitSurvey.script(lookups: Array(detector.all).sorted(), probe: "qzxwvutsrpon",
                                       configOption: "-F " + shellQuote(home + "/.ssh/config"))
        let (output, status) = try run(script)
        #expect(status == 0)
        return try BaitSurvey(output: output)
    }

    func file(_ name: String) -> String? { try? String(contentsOfFile: home + "/.ssh/" + name, encoding: .utf8) }

    @Test func theSurveySeesKeysPassphrasesAndEntries() throws {
        let survey = try survey()
        #expect(survey.home == home)
        #expect(Set(survey.keys.map(\.name)) == ["id_ed25519", "github_ed25519"])
        #expect(survey.keys.first { $0.name == "id_ed25519" }?.passphrase == true)
        #expect(survey.keys.first { $0.name == "github_ed25519" }?.publicLine != nil)
        #expect(survey.config == original)
        #expect(survey.resolved["devbox"]?["user"] == ["sam"])
        #expect(survey.resolved["github.com"]?["identityfile"]?.contains("~/.ssh/github_ed25519") == true)
        #expect(survey.known.contains("github.com"))
        #expect(!survey.known.contains("vault.example.ts.net"))
        #expect(survey.knownLines == 2)
    }

    @Test func aDecoyIsPlantedVerifiedRepeatedAndTakenOffAgain() throws {
        let before = try survey()
        var random = Seeded(state: 7)
        let plan = try BaitPlanner.plan(before, detector: detector, detectorPeer: nil, destination: "owner@laptop",
                                        makeKey: Self.makeKey, random: &random)
        let bait = plan.bait
        #expect(!BaitSurvey.defaultNames.contains(bait.keyFile))
        #expect(bait.keyFile.hasSuffix("_ed25519"))
        #expect(bait.account != before.user && bait.account != "root")
        #expect(bait.entry.contains("User \(bait.account)"))
        #expect(!bait.entry.contains("github") && !bait.entry.contains("devbox"))

        let write = BaitWrite.script(plan.writes, scratch: "scratch")
        var (output, status) = try run(write)
        #expect(BaitWrite.failure(output, status: status) == nil)
        let after = try survey()
        #expect(BaitPlanner.problem(bait, after) == nil)
        #expect(after.files[bait.keyFile]?.mode == 0o600)
        #expect(file("config")!.contains(bait.entry))
        // Run again, the same script changes nothing and still says ok.
        (output, status) = try run(write)
        #expect(BaitWrite.failure(output, status: status) == nil)
        #expect(try survey().files == after.files)

        let removal = try BaitPlanner.removal(bait, after)
        (output, status) = try run(BaitWrite.script(removal, scratch: "scratch"))
        #expect(BaitWrite.failure(output, status: status) == nil)
        #expect(file("config") == original)
        #expect(file(bait.keyFile) == nil)
        #expect(try BaitPlanner.removal(bait, try survey()).filter { if case .dropLine = $0 { false } else { true } }.isEmpty)
    }

    @Test func aWriteStopsWhenTheConfigChangedSinceTheSurvey() throws {
        var random = Seeded(state: 3)
        let plan = try BaitPlanner.plan(try survey(), detector: detector, detectorPeer: nil, destination: "laptop",
                                        makeKey: Self.makeKey, random: &random)
        try Data((original + "Host late\n  User x\n").utf8).write(to: URL(fileURLWithPath: home + "/.ssh/config"))
        let (output, status) = try run(BaitWrite.script(plan.writes, scratch: "scratch"))
        #expect(BaitWrite.failure(output, status: status) == "a file on the bait laptop changed since the survey")
        #expect(file(plan.bait.keyFile) == nil)
    }

    @Test func planningRefusesWhatItCantImitate() throws {
        let good = try survey()
        func refusal(_ change: (inout BaitSurvey) -> Void) -> String? {
            var survey = good
            change(&survey)
            var random = Seeded(state: 1)
            do {
                _ = try BaitPlanner.plan(survey, detector: detector, detectorPeer: nil, destination: "laptop", makeKey: Self.makeKey, random: &random)
                return nil
            } catch {
                return "\(error)"
            }
        }
        #expect(refusal { _ in } == nil)
        #expect(refusal { $0.keys.removeFirst() }?.contains("fewer than two") == true)
        #expect(refusal { survey in survey.keys = survey.keys.map { var key = $0; key.passphrase = true; return key } }?.contains("passphrase") == true)
        #expect(refusal { $0.resolved["devbox"]?["identityfile"] = ["~/.ssh/%h"] }?.contains("by destination") == true)
        #expect(refusal { survey in
            survey.keys = survey.keys.map { var key = $0; key.name = key.name == "github_ed25519" ? "id_rsa" : key.name; return key }
            survey.files["id_rsa"] = survey.files["github_ed25519"]
        }?.contains("formed like") == true)
        #expect(refusal { $0.resolved["devbox"]?["identityfile"] = ["~/.ssh/vault_ed25519"] }?.contains("would offer") == true)
    }

    @Test func aMachineTheLaptopReachesAlreadyGetsASecondAccountsName() throws {
        let reaching = original + "\nHost vault vault.example.ts.net\n  HostName vault.example.ts.net\n  HostKeyAlias vault\n  User owner\n"
        try Data(reaching.utf8).write(to: URL(fileURLWithPath: home + "/.ssh/config"))
        for seed in 1...6 as ClosedRange<UInt64> {
            var random = Seeded(state: seed)
            let plan = try BaitPlanner.plan(try survey(), detector: detector, detectorPeer: nil, destination: "laptop",
                                            makeKey: Self.makeKey, random: &random)
            let bait = plan.bait
            #expect(bait.patterns == ["vault_" + bait.account])
            #expect(!["owner", NSUserName(), "devbox", "vault", "github"].contains(bait.account))
            #expect(bait.hostName == "vault.example.ts.net")
            #expect(bait.keyFile == bait.account + "_ed25519")
        }
    }

    @Test func anyIdentityFileAnywhereAndAnInheritedPortAreRefused() throws {
        func plan(_ config: String) throws {
            try Data(config.utf8).write(to: URL(fileURLWithPath: home + "/.ssh/config"))
            var random = Seeded(state: 1)
            _ = try BaitPlanner.plan(try survey(), detector: detector, detectorPeer: nil, destination: "laptop",
                                     makeKey: Self.makeKey, random: &random)
        }
        // A block only a wildcard matches, naming the decoy's path another way.
        #expect(throws: Refusal("an IdentityFile on the bait laptop would offer a decoy")) {
            try plan(original + "Host *.corp\n  IdentityFile ~/.ssh/./vault_ed25519\n")
        }
        #expect(throws: Refusal("an IdentityFile on the bait laptop names keys by destination, so it could offer a decoy")) {
            try plan(original + "Match host *.corp\n  IdentityFile=~/.ssh/%n\n")
        }
        // Trailing spaces, which ssh drops.
        #expect(throws: Refusal("an IdentityFile on the bait laptop would offer a decoy")) {
            try plan(original + "Host *.corp\n  IdentityFile ~/.ssh/vault_ed25519   \n")
        }
        // An include written with =, holding the same, and one that includes another.
        try Data("Host *.corp\n  IdentityFile=~/.ssh/vault_ed25519\n".utf8).write(to: URL(fileURLWithPath: home + "/.ssh/extra"))
        #expect(throws: Refusal("an IdentityFile on the bait laptop would offer a decoy")) {
            try plan(original + "Include=~/.ssh/extra\n")
        }
        #expect(throws: Refusal("on the bait laptop, an ssh config includes a quoted path, which planting doesn't read")) {
            try plan(original + "Include \"~/.ssh/extra\"\n")
        }
        try Data("Include other\n".utf8).write(to: URL(fileURLWithPath: home + "/.ssh/extra"))
        #expect(throws: Refusal("on the bait laptop, an included ssh config includes another, which planting doesn't read")) {
            try plan(original + "include extra\n")
        }
        #expect(throws: Refusal("the bait laptop's entries reach SSH on another port than the detector's")) {
            try plan(original.replacingOccurrences(of: "  AddKeysToAgent yes", with: "  Port 2222"))
        }
    }

    @Test func aKilledRunsScratchIsClearedAndASharedKnownLineStays() throws {
        var random = Seeded(state: 9)
        let plan = try BaitPlanner.plan(try survey(), detector: detector, detectorPeer: nil, destination: "laptop",
                                        makeKey: Self.makeKey, random: &random)
        try Data("left by a killed run".utf8).write(to: URL(fileURLWithPath: home + "/.ssh/.scratch"))
        let (output, status) = try run(BaitWrite.script(plan.writes, scratch: "scratch"))
        #expect(BaitWrite.failure(output, status: status) == nil)
        #expect(file(".scratch") == nil)
        let bait = plan.bait
        #expect(bait.knownLine != nil)
        var after = try survey()
        #expect(try BaitPlanner.removal(bait, after).contains(.dropLine(name: "known_hosts", line: bait.knownLine!)))
        // Another entry, a rotation's new decoy say, looks the detector up by the same name.
        after.resolved["other"] = ["hostname": [bait.lookup], "user": ["x"]]
        #expect(!(try BaitPlanner.removal(bait, after)).contains(.dropLine(name: "known_hosts", line: bait.knownLine!)))
    }

    @Test func anAgentHoldingTheDecoyFailsVerification() throws {
        var random = Seeded(state: 5)
        let plan = try BaitPlanner.plan(try survey(), detector: detector, detectorPeer: nil, destination: "laptop",
                                        makeKey: Self.makeKey, random: &random)
        let (output, status) = try run(BaitWrite.script(plan.writes, scratch: "scratch"))
        #expect(BaitWrite.failure(output, status: status) == nil)
        var after = try survey()
        after.agent.append(plan.bait.key + " comment")
        #expect(BaitPlanner.problem(plan.bait, after) == "an agent on the bait laptop holds the decoy")
    }
}

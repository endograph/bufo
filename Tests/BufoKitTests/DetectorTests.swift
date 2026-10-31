@testable import BufoKit
import BufoContract
import Foundation
import Testing

struct SSHKeyTests {
    @Test func fingerprintsMatchSSHKeygen() throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        for type in ["ed25519", "ecdsa", "rsa"] {
            let key = directory + "/" + type
            #expect(System.run("/usr/bin/ssh-keygen", ["-q", "-t", type, "-N", "", "-C", "someone@somewhere", "-f", key]).status == 0)
            let line = try String(contentsOfFile: key + ".pub", encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines)
            let listed = String(data: System.run("/usr/bin/ssh-keygen", ["-l", "-E", "sha256", "-f", key + ".pub"]).output,
                                encoding: .utf8) ?? ""
            let parsed = try #require(SSHPublicKey(line: line))
            #expect(listed.split(separator: " ")[1] == parsed.fingerprint)
            #expect(SSHPublicKey.inDecoyLine(parsed.decoyLine) == parsed)
            #expect(!parsed.decoyLine.contains("someone"))
        }
    }

    @Test func onlyWholeKeysRead() {
        let blob = Data([0, 0, 0, 11] + Array("ssh-ed25519".utf8) + [0, 0, 0, 32] + Array(repeating: 7, count: 32))
        #expect(SSHPublicKey(line: "ssh-ed25519 \(blob.base64EncodedString())") != nil)
        #expect(SSHPublicKey(line: "ssh-rsa \(blob.base64EncodedString())") == nil)
        #expect(SSHPublicKey(line: "ssh-ed25519 not-base64") == nil)
        #expect(SSHPublicKey(line: "ssh-ed25519") == nil)
        #expect(SSHPublicKey.inDecoyLine("ssh-ed25519 \(blob.base64EncodedString())") == nil)
        #expect(SSHPublicKey.inDecoyLine("from=\"*\" ssh-ed25519 \(blob.base64EncodedString())") == nil)
    }
}

struct SSHDTests {
    @Test func uuidsMatchDwarfdump() {
        let listed = String(data: System.run("/usr/bin/dwarfdump", ["--uuid", SSHDIdentity.systemPath]).output, encoding: .utf8) ?? ""
        let expected = Set(listed.split(separator: "\n").compactMap { $0.split(separator: " ").dropFirst().first.map(String.init) })
        #expect(!expected.isEmpty)
        #expect(MachO.uuids(of: SSHDIdentity.systemPath) == expected)
        #expect(MachO.uuids(of: "/etc/hosts").isEmpty)
    }

    @Test func theFileSortsFirstAndLooksLikeItsNeighbours() throws {
        for _ in 0..<50 {
            let name = try #require(SSHDConfig.fileName(among: ["100-macos.conf": "UsePAM yes\n"], word: "watchd"))
            #expect(name.wholeMatch(of: /0\d\d-watchd\.conf/) != nil)
        }
        #expect(SSHDConfig.fileName(among: [:], word: "w")?.wholeMatch(of: /\d{3}-w\.conf/) != nil)
        #expect(SSHDConfig.fileName(among: ["01-a.conf": ""], word: "w") == nil)
        #expect(SSHDConfig.fileName(among: ["50-a.conf": "", "+early.conf": "  LogLevel INFO\n", "aaa.conf": "LogLevel INFO\n"], word: "w") == nil)
        #expect(SSHDConfig.fileName(among: ["50-a.conf": "", "zzz.conf": "LogLevel INFO\n"], word: "w")?.count == 9)
    }
}

struct ResumeTests {
    func event(_ second: Double, _ message: String, pid: Int32 = 1) -> LogEvent {
        Fixture.event(message, pid: pid, at: Fixture.start.addingTimeInterval(second))
    }

    @Test func historyUpToTheLastLineOnlyReplays() {
        let history = [event(0, "a"), event(1, "b"), event(2, "c"), event(3, "d")]
        let resumed = SSHDLog.resume(after: LogMark(history[1], boot: "B"), history: history, buffered: [event(3, "d"), event(4, "e")], boot: "B")
        #expect(resumed.reached)
        #expect(resumed.replay.map(\.eventMessage) == ["a", "b"])
        #expect(resumed.live.map(\.eventMessage) == ["c", "d", "e"])
    }

    @Test func historyThatNeverReachesTheLastLineIsAGap() {
        let gone = event(1, "b")
        let resumed = SSHDLog.resume(after: LogMark(gone, boot: "B"), history: [event(0, "a"), event(2, "c")], buffered: [], boot: "B")
        #expect(!resumed.reached)
        #expect(resumed.replay.map(\.eventMessage) == ["a"])
        #expect(resumed.live.map(\.eventMessage) == ["c"])
    }

    @Test func withNoLineTakenEverythingIsLive() {
        let resumed = SSHDLog.resume(after: nil, history: [event(0, "a")], buffered: [event(0, "a"), event(1, "b")], boot: "B")
        #expect(resumed.reached)
        #expect(resumed.replay.isEmpty)
        #expect(resumed.live.map(\.eventMessage) == ["a", "b"])
    }

    @Test func aDecoyUseCountsOnceAcrossARestart() {
        var before = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let use = Fixture.events(Fixture.decoyUse, pid: 9)
        let trips = use.prefix(3).map { before.consume($0) }.filter { if case .trip = $0 { true } else { false } }
        #expect(trips.count == 1)
        // The daemon restarts after the third line; the rest come after.
        var after = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let resumed = SSHDLog.resume(after: LogMark(use[2], boot: "B"), history: use, buffered: Array(use.suffix(2)), boot: "B")
        for event in resumed.replay { _ = after.consume(event) }
        #expect(resumed.live.map { after.consume($0) }.allSatisfy { $0 == .nothing })
    }

    @Test func theStoreRoundTrips() throws {
        var store = Store(watcher: UUID())
        store.decoys = [Fixture.decoy]
        store.lastSeen = LogMark(event(0.123456, "a"), boot: "B")
        let decoded = try JSONDecoder().decode(Store.self, from: JSONEncoder().encode(store))
        #expect(decoded.decoys == store.decoys)
        #expect(decoded.lastSeen == store.lastSeen)
        #expect(decoded.book.watcher == store.book.watcher)
    }
}

struct KeyInjectionTests {
    @Test func aTypeThatWouldAddALineIsRefused() {
        let type = "ssh-ed25519\nssh-ed25519"
        let blob = Data([0, 0, 0, UInt8(type.utf8.count)] + Array(type.utf8) + [0, 0, 0, 4, 1, 2, 3, 4])
        #expect(SSHPublicKey(line: "\(type) \(blob.base64EncodedString())") == nil)
        #expect(SSHPublicKey(line: "ssh-ed25519\tx \(blob.base64EncodedString())") == nil)
    }
}

struct DirectoryTests {
    @Test func recordsReadAsPresentOrAbsent() throws {
        #expect(try DecoyAccount.record("root") == .present(0))
        #expect(try DecoyAccount.record("_" + UUID().uuidString.prefix(12).lowercased()) == .absent)
    }
}

struct StreamAndHistoryTests {
    /// As a watcher's log reported one line both ways: the stream names no boot,
    /// its timestamp is 9 ms later, its Mach time 31 ticks off.
    @Test func aLineMatchesAcrossStreamAndHistory() {
        let shown = Fixture.event("Retrieve User by Name", at: Fixture.start)
        var streamed = shown
        streamed.bootUUID = ""
        streamed.timestamp = shown.timestamp.addingTimeInterval(0.009)
        streamed.machTimestamp += 31
        let showing = LogMark(shown, boot: "B")
        #expect(LogMark(streamed, boot: "B").matches(showing))
        #expect(SSHDLog.resume(after: LogMark(streamed, boot: "B"), history: [shown], buffered: [], boot: "B").reached)
        #expect(SSHDLog.resume(after: LogMark(streamed, boot: "B"), history: [shown], buffered: [streamed], boot: "B").live.isEmpty)
        var later = streamed
        later.machTimestamp += 7_800 * 10
        #expect(!LogMark(later, boot: "B").matches(showing))
        #expect(!LogMark(streamed, boot: "C").matches(showing))
    }
}

import BufoKit
import Foundation
import Testing

struct SSHTripTests {
    func run(_ events: [LogEvent], matcher: inout SSHTripMatcher) -> [SSHTripMatcher.Outcome] {
        events.map { matcher.consume($0) }.filter { $0 != .nothing }
    }

    @Test func oneUseIsOneTrip() throws {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let outcomes = run(Fixture.events(Fixture.decoyUse, pid: 47740), matcher: &matcher)
        #expect(outcomes.count == 1)
        guard case .trip(let trip) = try #require(outcomes.first) else { Issue.record("not a trip"); return }
        #expect(trip.decoy == Fixture.decoy.id)
        #expect(trip.address == "192.0.2.10")
        #expect(trip.port == 57740)
        #expect(trip.connection.hasPrefix("47740@"))
    }

    @Test func eachConnectionIsATrip() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let outcomes = run(Fixture.events(Fixture.decoyUse, pid: 1) + Fixture.events(Fixture.decoyUse, pid: 2), matcher: &matcher)
        #expect(outcomes.count == 2)
    }

    @Test func theOwnersLoginNeverTrips() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        #expect(run(Fixture.events(Fixture.ownerLogin, pid: 47731), matcher: &matcher).isEmpty)
    }

    @Test func theDecoyKeyForAnotherAccountTrips() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let line = "Failed publickey for owner from 192.0.2.10 port 1 ssh2: ED25519 \(Fixture.decoyFingerprint)"
        #expect(run([Fixture.event(line)], matcher: &matcher).count == 1)
    }

    @Test func anotherKeyForTheDecoyAccountTrips() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let line = "Failed publickey for builder from 192.0.2.10 port 1 ssh2: ED25519 \(Fixture.otherFingerprint)"
        #expect(run([Fixture.event(line)], matcher: &matcher).count == 1)
    }

    @Test func aReusedProcessIdIsANewConnection() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let later = Fixture.start.addingTimeInterval(60)
        let outcomes = run(Fixture.events(Fixture.decoyUse, pid: 3) + Fixture.events(Fixture.decoyUse, pid: 3, at: later),
                           matcher: &matcher)
        #expect(outcomes.count == 2)
    }

    @Test func localUseTrips() {
        // Through a relay on the watcher itself, the source is the watcher.
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let lines = Fixture.decoyUse.map { ($0.0.replacingOccurrences(of: "192.0.2.10", with: "127.0.0.1"), $0.1) }
        #expect(run(Fixture.events(lines, pid: 9), matcher: &matcher).count == 1)
    }

    @Test func aForgedLineNeverTrips() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        let forged = Fixture.event(Fixture.decoyUse[4].0, uid: 501, path: "/tmp/sshd-session", imageUUID: "F11E6B98-8A05-30E5-8443-21EC4BEFE047")
        #expect(run([forged], matcher: &matcher).isEmpty)
    }

    @Test func theProbeIsExemptOnceAndOnlyItself() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        matcher.expectProbe(Fixture.probeFingerprint, until: Fixture.start.addingTimeInterval(60))
        let probe = "Failed publickey for nobody from 127.0.0.1 port 5 ssh2: ED25519 \(Fixture.probeFingerprint)"
        #expect(run([Fixture.event(probe, pid: 5)], matcher: &matcher) == [.probeSeen(fingerprint: Fixture.probeFingerprint)])
        // Once seen, the same fingerprint again is nothing special: not a trip, not a probe.
        #expect(run([Fixture.event(probe, pid: 6)], matcher: &matcher).isEmpty)
        // An expected probe never exempts the decoy.
        matcher.expectProbe(Fixture.decoyFingerprint, until: Fixture.start.addingTimeInterval(60))
        #expect(run(Fixture.events(Fixture.decoyUse, pid: 7), matcher: &matcher).count == 1)
    }

    @Test func aProbeThatNeverCameIsOverdue() {
        var matcher = SSHTripMatcher(decoys: [Fixture.decoy], sshd: Fixture.sshd)
        matcher.expectProbe(Fixture.probeFingerprint, until: Fixture.start.addingTimeInterval(60))
        #expect(matcher.overdueProbes(now: Fixture.start.addingTimeInterval(30)).isEmpty)
        #expect(matcher.overdueProbes(now: Fixture.start.addingTimeInterval(61)) == [Fixture.probeFingerprint])
    }
}

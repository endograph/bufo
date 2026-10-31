import BufoContract
import BufoKit
import Foundation
import Testing

struct LedgerTests {
    static let watcher = UUID(uuidString: "00000000-0000-0000-0000-0000000000A1")!
    static let ids = (0..<8).map { UUID(uuidString: "00000000-0000-0000-0000-00000000010\($0)")! }

    func incident(_ n: Int, revision: UInt64 = 1, closed: Date? = nil) -> Update {
        .incident(Incident(id: Self.ids[n], revision: revision, kind: .sshKey, watcher: Self.watcher,
                           source: Source(address: "192.0.2.10"), firstSeen: Fixture.start, lastSeen: Fixture.start,
                           count: revision, connections: revision, closed: closed))
    }

    func alarm(_ sequence: UInt64) -> Update {
        .alarm(Alarm(watcher: Self.watcher, sequence: sequence, at: Fixture.start, subject: .heldBack(.observed, count: 1)))
    }

    @Test func eachRecipientGetsEverythingUntilItAcks() throws {
        var ledger = Ledger()
        ledger.add(recipient: "peer")
        ledger.add(recipient: "host")
        ledger.accept(incident(1))
        ledger.accept(alarm(1))
        let sent = ledger.pending(for: "peer")
        #expect(sent.map(\.update) == [incident(1), alarm(1)])
        ledger.ack("peer", through: try #require(sent.last).stamp)
        #expect(ledger.pending(for: "peer").isEmpty)
        // The peer's ack releases nothing the host hasn't taken.
        #expect(ledger.pending(for: "host").count == 2)
    }

    @Test func onlyNewRevisionsAndAlarmsAreTaken() {
        var ledger = Ledger()
        ledger.add(recipient: "host")
        let taken = [incident(1, revision: 1), incident(1, revision: 3), incident(1, revision: 2), alarm(1), alarm(1)]
            .map { ledger.accept($0) }
        #expect(taken == [true, true, false, true, false])
        #expect(ledger.pending(for: "host").map(\.update) == [incident(1, revision: 3), alarm(1)])
    }

    @Test func anOldRevisionAfterAnAckIsStillRefused() throws {
        var ledger = Ledger()
        ledger.add(recipient: "host")
        ledger.accept(incident(1, revision: 3))
        ledger.ack("host", through: try #require(ledger.pending(for: "host").last).stamp)
        let stale = ledger.accept(incident(1, revision: 2))
        #expect(!stale)
        ledger.accept(incident(1, revision: 4))
        #expect(ledger.pending(for: "host").map(\.update) == [incident(1, revision: 4)])
    }

    @Test func strangersAndOverreachingAcksChangeNothing() {
        var ledger = Ledger()
        ledger.add(recipient: "host")
        ledger.accept(incident(1))
        ledger.ack("stranger", through: 1)
        ledger.ack("host", through: 99)
        #expect(ledger.pending(for: "host").count == 1)
        #expect(ledger.pending(for: "stranger").isEmpty)
    }

    @Test func aFarBehindRecipientStillGetsCurrentState() {
        var ledger = Ledger()
        ledger.keepAlarms = 3
        ledger.add(recipient: "host")
        ledger.accept(incident(1, revision: 2, closed: Fixture.start))
        for n: UInt64 in 1...10 { ledger.accept(alarm(n)) }
        // The closing survives however many alarms follow; only the oldest alarms go.
        #expect(ledger.pending(for: "host").map(\.update) == [incident(1, revision: 2, closed: Fixture.start), alarm(8), alarm(9), alarm(10)])
    }

    @Test func aClosingIsNeverLostAndNeverUndone() throws {
        var ledger = Ledger()
        ledger.add(recipient: "host")
        ledger.accept(incident(1))
        ledger.ack("host", through: try #require(ledger.pending(for: "host").last).stamp)
        ledger.accept(incident(1, revision: 2, closed: Fixture.start))
        for n in 2..<8 { ledger.accept(incident(n, closed: Fixture.start)) }
        // However many closings follow, the host that missed this one still gets it,
        // and the open revision a lagging peer replays is refused.
        #expect(ledger.pending(for: "host").first?.update == incident(1, revision: 2, closed: Fixture.start))
        let stale = ledger.accept(incident(1))
        #expect(!stale)
    }

    @Test func anAlarmIsTakenOnceEvenAfterItsPayloadIsGone() throws {
        var ledger = Ledger()
        ledger.keepAlarms = 2
        for n: UInt64 in 1...3 { ledger.accept(alarm(n)) }
        var restored = try JSONDecoder().decode(Ledger.self, from: JSONEncoder().encode(ledger))
        let replayed = restored.accept(alarm(1))
        #expect(!replayed)
        let next = restored.accept(alarm(5))
        #expect(next)
    }

    @Test func noOtherWatcherRevisesAnIncident() {
        var ledger = Ledger()
        ledger.accept(incident(1))
        guard case .incident(var forged) = incident(1, revision: .max, closed: Fixture.start) else { return }
        forged.watcher = UUID()
        let taken = ledger.accept(.incident(forged))
        #expect(!taken)
        #expect(ledger.openIncidents.map(\.id) == [Self.ids[1]])
    }

    @Test func oneWatcherCantCrowdOutAnother() {
        var ledger = Ledger()
        ledger.keepAlarms = 2
        ledger.keepIncidents = 2
        ledger.add(recipient: "host")
        ledger.accept(alarm(1))
        let flood = UUID()
        for n: UInt64 in 1...10 {
            ledger.accept(.alarm(Alarm(watcher: flood, sequence: n, at: Fixture.start, subject: .heldBack(.observed, count: 1))))
            ledger.accept(.incident(Incident(id: UUID(), revision: 1, kind: .sshKey, watcher: flood, source: Source(address: nil),
                                             firstSeen: Fixture.start, lastSeen: Fixture.start, count: 1, connections: 1, closed: nil)),
                          fromPeer: true)
        }
        #expect(ledger.pending(for: "host").filter { $0.update.watcher == Self.watcher }.map(\.update) == [alarm(1)])
        #expect(ledger.openIncidents.count == 2)
        // This watcher's own are never refused.
        for n in 1...3 { ledger.accept(incident(n)) }
        #expect(ledger.openIncidents.count == 5)
    }

    @Test func aPeerGetsOnlyThisWatchersOwn() {
        var ledger = Ledger()
        ledger.add(recipient: "peer")
        let other = Update.alarm(Alarm(watcher: UUID(), sequence: 1, at: Fixture.start, subject: .heldBack(.health, count: 1)))
        ledger.accept(other)
        ledger.accept(alarm(1))
        #expect(ledger.pending(for: "peer", from: Self.watcher).map(\.update) == [alarm(1)])
        #expect(ledger.pending(for: "peer").count == 2)
    }

    @Test func survivesARestartBetweenStoringAndAcking() throws {
        var ledger = Ledger()
        ledger.add(recipient: "host")
        ledger.accept(incident(1))
        var restored = try JSONDecoder().decode(Ledger.self, from: JSONEncoder().encode(ledger))
        #expect(restored.pending(for: "host").count == 1)
        restored.accept(incident(2))
        #expect(restored.pending(for: "host").map(\.update) == [incident(1), incident(2)])
    }
}

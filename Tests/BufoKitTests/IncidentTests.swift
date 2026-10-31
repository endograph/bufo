import BufoContract
import BufoKit
import Foundation
import Testing

struct IncidentTests {
    let watcher = UUID(uuidString: "00000000-0000-0000-0000-0000000000A1")!
    let decoy = Fixture.decoy.id
    let source = Source(address: "192.0.2.10")

    func reasons(_ alarms: [Alarm]) -> [AlarmReason] {
        alarms.compactMap { if case .incident(_, let reason) = $0.subject { reason } else { nil } }
    }

    func trip(_ book: inout IncidentBook, decoy: UUID? = nil, source: Source? = nil, kind: DecoyKind = .sshKey,
              connection: String? = "1", after seconds: Double = 0) -> [Alarm] {
        book.record(decoy: decoy ?? self.decoy, kind: kind, source: source ?? self.source, connection: connection,
                    at: Fixture.start.addingTimeInterval(seconds)).alarms
    }

    @Test func repeatsMergeIntoOneIncident() {
        var book = IncidentBook(watcher: watcher)
        var alarms: [Alarm] = []
        for n in 0..<50 { alarms += trip(&book, connection: "\(n)", after: Double(n)) }
        #expect(book.openIncidents.count == 1)
        #expect(book.openIncidents.first?.count == 50)
        #expect(book.openIncidents.first?.connections == 50)
        #expect(reasons(alarms) == [.opened, .repeated])
    }

    @Test func alarmsAreNumberedInOrder() {
        var book = IncidentBook(watcher: watcher)
        var alarms: [Alarm] = []
        for n in 0..<3 { alarms += trip(&book, source: Source(address: "192.0.2.\(n)"), after: Double(n)) }
        #expect(alarms.map(\.sequence) == [1, 2, 3])
        #expect(book.alarmSequence == 3)
    }

    @Test func aNewSourceIsANewIncident() {
        var book = IncidentBook(watcher: watcher)
        _ = trip(&book)
        _ = trip(&book, source: Source(address: "192.0.2.11"))
        _ = trip(&book, source: Source(address: nil, name: "a", reportedBy: "host"))
        _ = trip(&book, source: Source(address: nil, name: "b", reportedBy: "host"))
        #expect(book.openIncidents.count == 4)
    }

    @Test func endlessSourcesStayBounded() {
        var rules = AlarmRules()
        rules.sourcesPerDecoy = 3
        var book = IncidentBook(watcher: watcher, rules: rules)
        for n in 0..<10 { _ = trip(&book, source: Source(address: "192.0.2.\(n)"), after: Double(n)) }
        #expect(book.openIncidents.count == 4)
        #expect(book.openIncidents.last?.source == Source(address: nil))
        #expect(book.openIncidents.last?.count == 7)
    }

    @Test func aConnectionAfterQuietAlarmsAgain() {
        var book = IncidentBook(watcher: watcher)
        _ = trip(&book)
        #expect(reasons(trip(&book, connection: "2", after: 3601)) == [.resumed])
    }

    @Test func steadyUseNeverSilencesForGood() {
        // A trip every 10 minutes for three days: alarms keep coming as reminders.
        var book = IncidentBook(watcher: watcher)
        var alarms: [Alarm] = []
        for n in 0..<(3 * 144) {
            alarms += trip(&book, connection: "\(n)", after: Double(n) * 600)
            alarms += book.tick(now: Fixture.start.addingTimeInterval(Double(n) * 600))
        }
        #expect(reasons(alarms).filter { $0 == .reminder }.count >= 2)
    }

    @Test func quietIncidentsStopRemindingButStayOpen() {
        var book = IncidentBook(watcher: watcher)
        _ = trip(&book)
        var reminders = 0
        for day in 1...10 { reminders += book.tick(now: Fixture.start.addingTimeInterval(Double(day) * 86_400 + 1)).count }
        #expect(reminders == 6)
        #expect(book.openIncidents.count == 1)
    }

    @Test func aFloodIsCountedHourlyAndItsIncidentsStillRemind() {
        var book = IncidentBook(watcher: watcher)
        var sent = 0
        for n in 0..<25 { sent += trip(&book, decoy: UUID(), after: Double(n)).count }
        #expect(sent == 10)
        #expect(book.openIncidents.count == 25)
        #expect(book.tick(now: Fixture.start.addingTimeInterval(30)).map(\.subject) == [.heldBack(.observed, count: 15)])
        #expect(book.tick(now: Fixture.start.addingTimeInterval(60)).isEmpty)
        // More held back within the hour waits for the next hourly count.
        for n in 0..<3 { _ = trip(&book, decoy: UUID(), after: 100 + Double(n)) }
        #expect(book.tick(now: Fixture.start.addingTimeInterval(1800)).isEmpty)
        #expect(book.tick(now: Fixture.start.addingTimeInterval(3631)).map(\.subject) == [.heldBack(.observed, count: 3)])
        // An incident whose opening was held back reminds a day after it opened, like any other, within the budget;
        // a reminder held back is counted once, however often the timer ticks.
        let day = book.tick(now: Fixture.start.addingTimeInterval(86_400 + 30))
        #expect(reasons(day).count == 10)
        #expect(day.last?.subject == .heldBack(.observed, count: 15))
        for minute in 1...59 { #expect(book.tick(now: Fixture.start.addingTimeInterval(86_400 + 30 + Double(minute) * 60)).isEmpty) }
        #expect(book.tick(now: Fixture.start.addingTimeInterval(86_400 + 3700)).map(\.subject) == [.heldBack(.observed, count: 3)])
    }

    @Test func eachHostHasItsOwnBudget() {
        var book = IncidentBook(watcher: watcher)
        for n in 0..<30 {
            _ = trip(&book, decoy: UUID(), source: Source(address: nil, reportedBy: "one"), kind: .hostCredential,
                     connection: nil, after: Double(n))
        }
        #expect(reasons(trip(&book, source: Source(address: nil, reportedBy: "two"), kind: .hostCredential, after: 31)) == [.opened])
        #expect(reasons(trip(&book, after: 32)) == [.opened])
    }

    @Test func closingStopsAlarmsAndTheNextTripOpensAnew() throws {
        var book = IncidentBook(watcher: watcher)
        _ = trip(&book)
        let id = try #require(book.openIncidents.first?.id)
        #expect(book.close(id, at: Fixture.start.addingTimeInterval(10))?.closed != nil)
        #expect(book.openIncidents.isEmpty)
        #expect(book.tick(now: Fixture.start.addingTimeInterval(2 * 86_400)).isEmpty)
        #expect(reasons(trip(&book, connection: "2", after: 20)) == [.opened])
        #expect(book.openIncidents.first?.id != id)
    }

    @Test func theBookSurvivesARestart() throws {
        var book = IncidentBook(watcher: watcher)
        for n in 0..<9 { _ = trip(&book, connection: "\(n)", after: Double(n)) }
        var restored = try JSONDecoder().decode(IncidentBook.self, from: JSONEncoder().encode(book))
        let tenth = trip(&restored, connection: "9", after: 9)
        #expect(reasons(tenth) == [.repeated])
        #expect(tenth.first?.sequence == 2)
        #expect(restored.openIncidents.count == 1)
    }
}

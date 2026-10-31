import BufoContract
import Foundation

/// The rules for alarms. Recording is never budgeted, only alarms.
public struct AlarmRules: Codable, Sendable, Equatable {
    /// Repeats at which an open incident alarms again.
    public var repeatAlarms: [UInt64] = [10, 100]
    /// Quiet after which a new connection alarms again.
    public var resumeAfter: TimeInterval = 3600
    /// An open incident alarms at least this often while it is active.
    public var reminderEvery: TimeInterval = 86_400
    /// An incident quiet this long stops reminding, and stays open.
    public var remindFor: TimeInterval = 7 * 86_400
    /// Alarms per budget per hour; the rest are counted, and the count is
    /// an alarm of its own at most hourly.
    public var perHour = 10
    /// Open incidents one decoy may have; trips from further sources count
    /// on one more incident whose source is unknown.
    public var sourcesPerDecoy = 64

    public init() {}
}

/// The incidents this watcher detected that are still open, and the alarms
/// it decides about them. What it returns goes to the `Ledger`, which keeps
/// closed incidents too. Codable, so the store keeps it across restarts.
public struct IncidentBook: Codable, Sendable {
    private var incidents: [UUID: Incident] = [:]
    public var rules: AlarmRules
    public let watcher: UUID
    /// The last alarm's number in this watcher's sequence.
    public private(set) var alarmSequence: UInt64 = 0
    /// Open incidents by (decoy, source), with what deciding their alarms takes.
    private var open: [Key: Open] = [:]
    private var budgets: [AlarmBudget: Budget] = [:]

    struct Key: Hashable, Codable, Sendable {
        var decoy: UUID
        var source: String?
        var reportedBy: String?

        init(_ decoy: UUID, _ source: Source) {
            self.decoy = decoy
            self.source = source.address ?? source.name
            reportedBy = source.reportedBy
        }

        var budget: AlarmBudget { reportedBy.map(AlarmBudget.host) ?? .observed }
    }

    struct Open: Codable, Sendable {
        var id: UUID
        var lastConnection: String?
        var lastAlarm: Date?
    }

    struct Budget: Codable, Sendable {
        var sent: [Date] = []
        var held = 0
        var lastHeldNotice: Date?
    }

    public init(watcher: UUID, rules: AlarmRules = AlarmRules()) {
        self.watcher = watcher
        self.rules = rules
    }

    /// Records one trip of `decoy` from `source` at `at` (the watcher's own
    /// receipt time), on `connection` if it came over one. Returns the
    /// incident as it now stands, and the alarm it raised, if any.
    public mutating func record(decoy: UUID, kind: DecoyKind, source: Source, connection: String?,
                                at: Date) -> (incident: Incident, alarms: [Alarm]) {
        var source = source
        var key = Key(decoy, source)
        if open[key] == nil, open.keys.count(where: { $0.decoy == decoy }) >= rules.sourcesPerDecoy {
            source = Source(address: nil, reportedBy: source.reportedBy)
            key = Key(decoy, source)
        }
        guard let entry = open[key], var incident = incidents[entry.id] else {
            let incident = Incident(id: UUID(), revision: 1, kind: kind, watcher: watcher, source: source, firstSeen: at,
                                    lastSeen: at, count: 1, connections: connection == nil ? 0 : 1, closed: nil)
            incidents[incident.id] = incident
            open[key] = Open(id: incident.id, lastConnection: connection)
            return (incident, alarm(key, .opened, at: at))
        }
        let quiet = at.timeIntervalSince(incident.lastSeen)
        let newConnection = connection.map { $0 != entry.lastConnection } ?? false
        incident.count += 1
        if newConnection { incident.connections += 1 }
        incident.lastSeen = max(incident.lastSeen, at)
        incident.revision += 1
        incidents[incident.id] = incident
        if let connection { open[key]?.lastConnection = connection }
        let reason: AlarmReason? = if rules.repeatAlarms.contains(incident.count) {
            .repeated
        } else if newConnection, quiet >= rules.resumeAfter {
            .resumed
        } else {
            nil
        }
        return (incident, reason.map { alarm(key, $0, at: at) } ?? [])
    }

    /// Reminders for open incidents still active, and each budget's count of
    /// alarms held back, at most hourly.
    public mutating func tick(now: Date) -> [Alarm] {
        var alarms: [Alarm] = []
        for (key, entry) in open.sorted(by: { $0.value.id.uuidString < $1.value.id.uuidString }) {
            guard let incident = incidents[entry.id], now.timeIntervalSince(incident.lastSeen) < rules.remindFor,
                  now.timeIntervalSince(entry.lastAlarm ?? incident.firstSeen) >= rules.reminderEvery else { continue }
            alarms += alarm(key, .reminder, at: now)
        }
        for (kind, var budget) in budgets.sorted(by: { "\($0.key)" < "\($1.key)" }) {
            guard budget.held > 0, budget.lastHeldNotice.map({ now.timeIntervalSince($0) >= 3600 }) ?? true else { continue }
            alarms.append(next(.heldBack(kind, count: budget.held), at: now))
            budget.held = 0
            budget.lastHeldNotice = now
            budgets[kind] = budget
        }
        return alarms
    }

    /// Closes an incident (root at the watcher): the book lets it go, it
    /// stops alarming, and the next trip from that source opens a new one.
    public mutating func close(_ id: UUID, at: Date) -> Incident? {
        guard var incident = incidents.removeValue(forKey: id) else { return nil }
        incident.closed = at
        incident.revision += 1
        open = open.filter { $0.value.id != id }
        return incident
    }

    public var openIncidents: [Incident] {
        incidents.values.sorted { $0.firstSeen < $1.firstSeen }
    }

    /// An alarm about a peer (silent, stopped, back, degraded, covered), if the
    /// health budget has room.
    public mutating func peer(_ watcher: UUID?, address: String, _ change: PeerChange, at: Date) -> [Alarm] {
        admit(.health, at: at) ? [next(.peer(watcher: watcher, address: address, change), at: at)] : []
    }

    /// An alarm for the open incident at `key`, if its budget has room. One
    /// held back counts as given for timing: the hourly count stands for it.
    private mutating func alarm(_ key: Key, _ reason: AlarmReason, at: Date) -> [Alarm] {
        guard let id = open[key]?.id, let incident = incidents[id] else { return [] }
        open[key]?.lastAlarm = at
        return admit(key.budget, at: at) ? [next(.incident(incident, reason), at: at)] : []
    }

    /// Whether `kind` has room for one more alarm this hour; one without is
    /// counted toward the hourly held-back alarm.
    private mutating func admit(_ kind: AlarmBudget, at: Date) -> Bool {
        var budget = budgets[kind] ?? Budget()
        budget.sent = budget.sent.filter { at.timeIntervalSince($0) < 3600 }
        defer { budgets[kind] = budget }
        guard budget.sent.count < rules.perHour else {
            budget.held += 1
            return false
        }
        budget.sent.append(at)
        return true
    }

    private mutating func next(_ subject: Alarm.Subject, at: Date) -> Alarm {
        alarmSequence += 1
        return Alarm(watcher: watcher, sequence: alarmSequence, at: at, subject: subject)
    }
}

import BufoContract
import Foundation

/// What this watcher knows (its own incidents and alarms, and those its peers
/// sent) and how far each recipient (a peer, a host) has taken it. Every
/// update it accepts takes the next stamp; a recipient is sent what is newer
/// than its cursor, oldest first, until it acks, so each gets everything at
/// least once and in order, and one recipient's ack releases nothing for
/// another. Codable, so the store keeps it, written before anything is sent.
///
/// Every incident is kept, in its newest revision only, so a recipient
/// however far behind still gets current state and a stale revision is
/// always refused. They grow only as root closes them: open ones are bounded
/// per decoy (`AlarmRules.sourcesPerDecoy`). The newest `keepAlarms` alarms
/// are kept; a recipient further behind sees the gap in their sequence.
///
/// Each watcher's alarms arrive in its order, since a watcher sends a peer
/// only its own updates (`pending(for:from:)`), over one connection at a
/// time, in stamp order; so an alarm is new when its number is past the last
/// one taken from that watcher. A transport that let an unseen alarm arrive
/// after a later one would lose it.
public struct Ledger: Codable, Sendable {
    private var incidents: [UUID: Entry] = [:]
    private var alarms: [Entry] = []
    private var lastAlarm: [UUID: UInt64] = [:]
    private var stamp: UInt64 = 0
    private var cursors: [String: UInt64] = [:]
    public var keepAlarms = 4096
    /// Incidents taken per peer watcher, so one peer can't grow the store
    /// without bound; past it a new incident from that peer is refused. This
    /// watcher's own are never refused (PLAN.md, recording is never budgeted).
    public var keepIncidents = 4096

    public typealias Entry = Stamped

    public init() {}

    /// Takes an incident revision newer than the one held, or an alarm past
    /// the last from its watcher; returns whether it took it. `fromPeer`
    /// holds a peer's incidents to `keepIncidents`.
    @discardableResult
    public mutating func accept(_ update: Update, fromPeer: Bool = false) -> Bool {
        switch update {
        case .incident(let incident):
            if case .incident(let held)? = incidents[incident.id]?.update {
                // An incident stays its detecting watcher's: no other may revise it.
                guard held.watcher == incident.watcher, held.revision < incident.revision else { return false }
            } else if fromPeer, incidents.values.count(where: { $0.update.watcher == incident.watcher }) >= keepIncidents {
                return false
            }
            stamp += 1
            incidents[incident.id] = Entry(stamp: stamp, update: update)
        case .alarm(let alarm):
            guard alarm.sequence > lastAlarm[alarm.watcher, default: 0] else { return false }
            lastAlarm[alarm.watcher] = alarm.sequence
            stamp += 1
            alarms.append(Entry(stamp: stamp, update: update))
            // Each watcher's alarms are kept apart, so one can't push out another's.
            if alarms.count(where: { $0.update.watcher == alarm.watcher }) > keepAlarms,
               let oldest = alarms.firstIndex(where: { $0.update.watcher == alarm.watcher }) {
                alarms.remove(at: oldest)
            }
        }
        return true
    }

    public var openIncidents: [Incident] {
        incidents.values.compactMap { if case .incident(let incident) = $0.update, incident.closed == nil { incident } else { nil } }
            .sorted { $0.firstSeen < $1.firstSeen }
    }

    public var recipients: [String] { cursors.keys.sorted() }

    /// The last alarm taken from `watcher`.
    public func lastAlarm(from watcher: UUID) -> UInt64 { lastAlarm[watcher, default: 0] }

    /// The stamp of the last update accepted.
    public var lastStamp: UInt64 { stamp }

    /// A new recipient starts with everything held.
    public mutating func add(recipient: String) {
        if cursors[recipient] == nil { cursors[recipient] = 0 }
    }

    public mutating func remove(recipient: String) {
        cursors[recipient] = nil
    }

    /// What `recipient` hasn't acked, oldest first; for a peer, only what
    /// `origin` (this watcher) detected or decided. A host gets everything.
    public func pending(for recipient: String, from origin: UUID? = nil) -> [Entry] {
        guard let cursor = cursors[recipient] else { return [] }
        return (incidents.values + alarms).filter { $0.stamp > cursor && (origin == nil || $0.update.watcher == origin) }
            .sorted { $0.stamp < $1.stamp }
    }

    /// `recipient` holds everything through `stamp`. An ack beyond what was
    /// accepted, or from no recipient, changes nothing.
    public mutating func ack(_ recipient: String, through stamp: UInt64) {
        guard let cursor = cursors[recipient], stamp > cursor, stamp <= self.stamp else { return }
        cursors[recipient] = stamp
    }
}

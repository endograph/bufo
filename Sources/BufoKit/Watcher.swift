import BufoContract
import Foundation
import Network
import os

/// The daemon's work (PLAN.md, The SSH-key decoy; Watcher to watcher): it
/// arms and retires decoys, streams sshd's log and reads back what a gap
/// missed, turns trips into incidents and alarms, runs the self-test,
/// checks that what it armed is still as armed, and trades its ledger and
/// health with its peers (`Watcher+Peers`). Everything runs on `queue`;
/// the store is saved within a second of any change, and at once after a
/// trip or a change of decoys.
public final class Watcher: @unchecked Sendable {
    let queue = DispatchQueue(label: "watcher")
    let state: String
    let word: String
    let version: Int
    let log: Logger
    var store: Store
    var matcher: SSHTripMatcher?
    var stream: SSHDStream?
    /// While a (re)started stream waits for history, what it streamed.
    var buffered: [LogEvent]?
    /// After it, the lines history read, until the stream passes the last of
    /// them: the stream may still deliver some it had read but not handed on.
    var overlap: (marks: LogMarks, last: LogMark)?
    /// This boot's id, for streamed lines, which name none.
    let boot: String
    /// Each start of watching; callbacks from an earlier one are ignored.
    var generation = 0
    var problems: [String] = []
    var dirty = false
    var nextSelfTest: Date?
    var selfTestRunning = false
    var nextCheck = Date.distantPast
    var timer: DispatchSourceTimer?
    let started = Date()
    /// Since when this watcher has run without a stall (a freeze, or the
    /// machine asleep): it can't judge a peer's silence from before.
    var awake = Date()
    var lastTick = Date()
    /// Peer connections: authenticated ones by peer, and the listener's.
    var links: [UUID: PeerLink] = [:]
    var inFlight: [UUID: UInt64] = [:]
    var listener: NWListener?
    var unproven: [String: PeerLink] = [:]
    /// Outbound connections not yet proven, held until they are or close.
    var dialing: [UUID: PeerLink] = [:]
    var backoff: [UUID: TimeInterval] = [:]
    var healthSequence: UInt64 = 0
    /// The ledger's stamp at the last save: nothing past it is sent.
    var savedThrough: UInt64 = 0
    var nextHealth = Date.distantPast
    /// Planting requests sent to a peer, waiting for its answer.
    var answers: [UUID: (peer: UUID, reply: (String?) -> Void)] = [:]
    /// Hosts with an `updates` call waiting.
    var polling: Set<UUID> = []

    /// At most this many decoys at once: a few (ARCHITECTURE.md, The planting grant).
    static let maxDecoys = 4
    static let selfTestEvery: TimeInterval = 3 * 3600
    static let selfTestWait: TimeInterval = 60
    static let checkEvery: TimeInterval = 600
    static let restartAfter: TimeInterval = 5
    static let maxBuffered = 100_000
    /// Ticks come each second; a gap this long is a stall.
    static let stall: TimeInterval = 30

    /// `word` names Bufo's sshd file; `version` is the running build's.
    public init(state: String, word: String, watcher: UUID, version: Int, log: Logger) throws {
        self.state = state
        self.word = word
        self.version = version
        self.log = log
        store = try Store.load(state, watcher: watcher)
        savedThrough = store.ledger.lastStamp
        var size = 64
        var id = [CChar](repeating: 0, count: size)
        guard sysctlbyname("kern.bootsessionuuid", &id, &size, nil, 0) == 0 else { throw Refusal("this boot's id doesn't read") }
        boot = String(decoding: id.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }, as: UTF8.self)
    }

    public func start() {
        queue.async { [self] in
            // Key pairs a crash left mid-plant (`makeKey`).
            for name in (try? FileManager.default.contentsOfDirectory(atPath: state)) ?? [] where name.hasPrefix(".key-") {
                try? FileManager.default.removeItem(atPath: state + "/" + name)
            }
            if !store.decoys.isEmpty { watch() }
            startPeers()
            let timer = DispatchSource.makeTimerSource(queue: queue)
            timer.schedule(deadline: .now() + 1, repeating: 1)
            timer.setEventHandler { [weak self] in self?.tick() }
            timer.resume()
            self.timer = timer
        }
    }

    /// Stops the stream, tells peers this watcher is stopping, and saves,
    /// for SIGTERM.
    public func stop() {
        let sent = DispatchGroup()
        queue.sync {
            generation += 1
            stream?.stop()
            save()
            for link in links.values {
                sent.enter()
                link.send(.stopping) { sent.leave() }
            }
        }
        _ = sent.wait(timeout: .now() + 2)
    }

    // MARK: Requests

    public func status() -> Status {
        queue.sync {
            let watching = !store.decoys.isEmpty
            return Status(installed: true, watcher: store.book.watcher, version: version, kinds: kinds,
                          coverage: coverage, lastSelfTest: store.lastSelfTest,
                          openIncidents: Dictionary(grouping: store.ledger.openIncidents, by: \.kind).mapValues(\.count),
                          peers: peerStatuses(), baits: store.baits.count, hosts: hostStatuses(), delivering: delivering(),
                          notes: [store.coverageProblem, store.planting.map { _ in "a planting is unfinished: run bufo resume" },
                                  (watching || store.peers.contains(where: \.mayPlant)) && !System.fullDiskAccess
                                    ? "the daemon lacks Full Disk Access, so it can't remove decoys' accounts" : nil]
                            .compactMap { $0 } + problems + ["the store is unencrypted until v1"])
        }
    }

    /// The kinds of decoy armed here: SSH keys, and hosts' own credentials.
    var kinds: [DecoyKind] {
        (store.decoys.isEmpty ? [] : [.sshKey]) + (store.hosts.contains { !$0.registered.isEmpty } ? [.hostCredential] : [])
    }

    /// This watcher's coverage, as `status` and its health say it. Reading
    /// history back after a restart is still full: the stream is buffered,
    /// and a catch-up that fails degrades.
    var coverage: Coverage {
        guard !store.decoys.isEmpty else { return .off }
        return stream == nil || store.coverageProblem != nil || !problems.isEmpty ? .degraded : .full
    }

    /// Arms an SSH decoy: `account`, made for the key on `keyLine`, for root here.
    public func arm(account: String, keyLine: String) throws {
        try queue.sync { try arm(account: account, keyLine: keyLine, by: nil) }
    }

    /// Retires the decoy whose account is `account`, for root here. Its incidents stay open.
    public func retire(account: String) throws {
        try queue.sync { try retire(account: account, by: nil) }
    }

    /// Arms a decoy on the queue, for root here or, under the planting grant,
    /// the peer `by`. What it makes is recorded first, so a crash leaves
    /// nothing retire and uninstall can't find.
    func arm(account: String, keyLine: String, by peer: UUID?) throws {
        do {
            guard System.fullDiskAccess else {
                throw Refusal("this watcher's daemon needs Full Disk Access to remove a decoy's account later: "
                              + "add \(Bundle.main.executablePath ?? "its binary") in System Settings, Privacy & Security")
            }
            guard let key = SSHPublicKey(line: keyLine) else { throw Refusal("that isn't an SSH public key") }
            guard !store.decoys.contains(where: { $0.fingerprint == key.fingerprint || $0.account == account }) else {
                throw Refusal("that decoy is already armed")
            }
            guard store.decoys.count < Self.maxDecoys else { throw Refusal("\(Self.maxDecoys) decoys are armed already") }
            var decoy = try DecoyAccount.plan(account, key: key)
            decoy.armedBy = peer
            if store.sshdFile == nil { store.sshdFile = try SSHDConfig.chooseName(word: word) }
            store.decoys.append(decoy)
            store.armedAt = store.armedAt ?? Date()
            do {
                try store.save(state)
                try SSHDConfig.set(file: store.sshdFile!)
                try DecoyAccount.create(decoy, key: key)
            } catch {
                if (try? DecoyAccount.remove(decoy)) != nil { store.decoys.removeAll { $0.id == decoy.id } }
                if store.decoys.isEmpty { try? unset() }
                save()
                throw error
            }
            log.notice("armed a decoy; \(self.store.decoys.count, privacy: .public) now")
            if matcher == nil { watch() } else { matcher?.decoys = store.decoys }
            check()
        }
    }

    /// Arms a decoy unless the same hand armed it with the same key already;
    /// one a crash left half made (its account or key line not as armed) is
    /// retired and armed again, so a repeated request ends armed.
    func armOnce(account: String, keyLine: String, by peer: UUID?) throws {
        if let armed = store.decoys.first(where: { $0.account == account && $0.armedBy == peer }),
           armed.fingerprint == SSHPublicKey(line: keyLine)?.fingerprint {
            guard !DecoyAccount.problems(armed).isEmpty else { return }
            try retire(account: account, by: peer)
        }
        try arm(account: account, keyLine: keyLine, by: peer)
    }

    /// Retires a decoy on the queue: any, for root here; only its own, for a peer.
    func retire(account: String, by peer: UUID?) throws {
        do {
            guard let decoy = store.decoys.first(where: { $0.account == account && (peer == nil || $0.armedBy == peer) }) else {
                throw Refusal("no decoy has that account")
            }
            try DecoyAccount.remove(decoy)
            store.decoys.removeAll { $0.id == decoy.id }
            if store.decoys.isEmpty {
                stopWatching()
                do {
                    try unset()
                } catch {
                    save()
                    throw error
                }
            } else {
                matcher?.decoys = store.decoys
            }
            try saveNow()
            log.notice("retired a decoy; \(self.store.decoys.count, privacy: .public) left")
            check()
        }
    }

    // MARK: Watching

    /// Starts the stream, buffering it, and reads back history from where
    /// the last line was taken; then takes both (`caughtUp`).
    func watch() {
        generation += 1
        let generation = generation
        let sshd = SSHDIdentity(uuids: MachO.uuids(of: SSHDIdentity.systemPath))
        matcher = SSHTripMatcher(decoys: store.decoys, sshd: sshd)
        buffered = []
        overlap = nil
        nextSelfTest = Date().addingTimeInterval(Self.selfTestWait)
        let stream = SSHDStream(sshd, queue: queue, event: { [weak self] in self?.received($0, generation) },
                                ended: { [weak self] in self?.ended(generation) })
        self.stream = stream
        do {
            try stream.start()
        } catch {
            ended(generation)
            return
        }
        let since = store.lastSeen.map { $0.at.addingTimeInterval(-SSHTripMatcher.connectionWindow) } ?? store.armedAt ?? Date()
        DispatchQueue.global().async { [weak self] in
            let history = SSHDLog.history(sshd, since: since)
            guard let self else { return }
            self.queue.async { self.caughtUp(history, generation) }
        }
    }

    func stopWatching() {
        generation += 1
        stream?.stop()
        stream = nil
        matcher = nil
        buffered = nil
    }

    func caughtUp(_ history: [LogEvent]?, _ generation: Int) {
        guard generation == self.generation, let streamed = buffered else { return }
        buffered = nil
        guard let history else {
            degrade("sshd's log history didn't read")
            streamed.forEach(take)
            return
        }
        let resumed = SSHDLog.resume(after: store.lastSeen, history: history, buffered: streamed, boot: boot)
        for event in resumed.replay { _ = matcher?.consume(event) }
        resumed.live.forEach(take)
        overlap = history.last.map { (LogMarks(history.map { LogMark($0, boot: boot) }), LogMark($0, boot: boot)) }
        if !resumed.reached { degrade("sshd's log has a gap that couldn't be read back") }
    }

    func received(_ event: LogEvent, _ generation: Int) {
        guard generation == self.generation else { return }
        guard buffered == nil else {
            buffered?.append(event)
            if buffered!.count > Self.maxBuffered {
                degrade("sshd's log came faster than history could be read")
                buffered = []
            }
            return
        }
        if let overlap {
            let mark = LogMark(event, boot: boot)
            if !overlap.last.covers(mark) {
                self.overlap = nil
            } else if overlap.marks.contains(mark) {
                return
            }
        }
        take(event)
    }

    /// A stream that ends is degraded coverage until a self-test passes on
    /// the next one (PLAN.md, Coverage).
    func ended(_ generation: Int) {
        guard generation == self.generation else { return }
        stream = nil
        degrade("sshd's log stream ended")
        queue.asyncAfter(deadline: .now() + Self.restartAfter) { [weak self] in
            guard let self, generation == self.generation, !self.store.decoys.isEmpty else { return }
            self.watch()
        }
    }

    /// Takes one line. A trip is saved at once with the line it came from
    /// as the last taken, so a restart never counts it again.
    func take(_ event: LogEvent) {
        guard matcher != nil else { return }
        let outcome = matcher!.consume(event)
        store.lastSeen = LogMark(event, boot: boot)
        dirty = true
        switch outcome {
        case .trip(let trip):
            record(trip)
            save()
            deliver()
        case .probeSeen: passed()
        case .nothing: break
        }
    }

    /// Records a trip at the watcher's own receipt time (PLAN.md, Incidents).
    func record(_ trip: Trip) {
        let (incident, alarms) = store.book.record(decoy: trip.decoy, kind: .sshKey, source: Source(address: trip.address),
                                                   connection: trip.connection, at: Date())
        store.ledger.accept(.incident(incident))
        alarms.forEach(raise)
        if store.evidence[incident.id, default: []].count < Store.evidenceLines {
            store.evidence[incident.id, default: []].append(trip.evidence)
        }
    }

    func raise(_ alarm: Alarm) {
        store.ledger.accept(.alarm(alarm))
        switch alarm.subject {
        case .incident(let incident, let reason):
            log.error("""
                alarm \(alarm.sequence, privacy: .public): \(incident.kind.rawValue, privacy: .public) \
                \(reason.rawValue, privacy: .public) from \(incident.source.address ?? "an unknown source", privacy: .public), \
                \(incident.count, privacy: .public) trips
                """)
        case .heldBack(_, let count):
            log.error("alarm \(alarm.sequence, privacy: .public): \(count, privacy: .public) alarms held back this hour")
        case .peer(_, let address, let change):
            log.error("alarm \(alarm.sequence, privacy: .public): the peer at \(address, privacy: .public) \(change.rawValue, privacy: .public)")
        }
        dirty = true
    }

    // MARK: Self-test, checks, and the clock

    func tick() {
        let now = Date()
        if now.timeIntervalSince(lastTick) > Self.stall { awake = now }
        lastTick = now
        store.book.tick(now: now).forEach(raise)
        if matcher != nil, !(matcher!.overdueProbes(now: now)).isEmpty {
            degrade("the self-test's key didn't come back through sshd's log")
            nextSelfTest = now.addingTimeInterval(Self.checkEvery)
        }
        if stream != nil, buffered == nil, let due = nextSelfTest, now >= due {
            nextSelfTest = now.addingTimeInterval(Self.selfTestEvery + .random(in: -1800...1800))
            selfTest()
        }
        if now >= nextCheck {
            nextCheck = now.addingTimeInterval(Self.checkEvery)
            check()
        }
        watchPeers(now: now)
        if dirty { save() }
        deliver()
    }

    func selfTest() {
        guard !selfTestRunning else { return }
        guard let account = store.selfTestAccount ?? SelfTest.chooseAccount() else {
            degrade("no built-in account to self-test with")
            return
        }
        store.selfTestAccount = account
        selfTestRunning = true
        let state = state
        DispatchQueue.global().async { [weak self] in
            guard let self else { return }
            if let made = SelfTest.makeKey(in: state) {
                self.queue.sync {
                    self.matcher?.expectProbe(made.fingerprint, until: Date().addingTimeInterval(Self.selfTestWait))
                }
                SelfTest.offer(made.key, account: account)
                try? FileManager.default.removeItem(atPath: made.directory)
            } else {
                self.queue.async { self.degrade("the self-test couldn't make a key") }
            }
            self.queue.async { self.selfTestRunning = false }
        }
    }

    func passed() {
        store.lastSelfTest = Date()
        if let problem = store.coverageProblem {
            log.notice("coverage is full again after: \(problem, privacy: .public)")
            store.coverageProblem = nil
        }
        dirty = true
    }

    func degrade(_ problem: String) {
        guard store.coverageProblem == nil else { return }
        store.coverageProblem = problem
        log.error("coverage degraded: \(problem, privacy: .public)")
        dirty = true
    }

    func check() {
        var found = store.decoys.flatMap(DecoyAccount.problems)
        if let file = store.sshdFile { found += SSHDConfig.problems(file: file) }
        if found != problems {
            for problem in found where !problems.contains(problem) { log.error("\(problem, privacy: .public)") }
            problems = found
        }
    }

    /// Takes back sshd's file once no decoy needs it; the next arming starts
    /// from nothing. Kept in the store until it's gone.
    func unset() throws {
        try SSHDConfig.remove(file: store.sshdFile)
        store.sshdFile = nil
        store.lastSeen = nil
        store.armedAt = nil
        store.coverageProblem = nil
    }

    func save() {
        do {
            try saveNow()
        } catch {
            log.error("the store didn't save: \(String(describing: error), privacy: .public)")
        }
    }
}

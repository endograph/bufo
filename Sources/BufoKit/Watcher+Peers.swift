import BufoContract
import Foundation
import Network

/// Watcher to watcher (PLAN.md, section 5): pinning, the listener and the
/// dialer, proof of the pair's key, ledger delivery and acks, health, the
/// silence and degraded-coverage alarms, and the planting grant. Runs on
/// the watcher's queue like everything else.
extension Watcher {
    static let healthEvery: TimeInterval = 60
    static let silentAfter: TimeInterval = 300
    static let proofWait: TimeInterval = 5
    static let maxBackoff: TimeInterval = 60
    static let batch = 32

    // MARK: Pinning, by root here

    /// Sets where this watcher listens for peers: its tailnet address.
    public func listen(address: String, port: UInt16) throws {
        try queue.sync {
            guard Self.isAddress(address), port > 0 else { throw Refusal("that isn't an IP address and port") }
            store.listen = Listener(address: address, port: port)
            try saveNow()
            restartListener()
        }
    }

    /// Pins the peer at `address`, dialing it at `port` if given, with the
    /// pairing code `code` from the other side, or a new one, returned.
    public func addPeer(address: String, port: UInt16?, mayPlant: Bool, code text: String?) throws -> String? {
        try queue.sync {
            guard Self.isAddress(address), port != 0 else { throw Refusal("that isn't an IP address and port") }
            guard !store.peers.contains(where: { PeerTLS.same($0.address, address) }) else {
                throw Refusal("a peer at that address is pinned already")
            }
            let code: PairingCode
            if let text {
                guard let read = PairingCode(text) else { throw Refusal("that isn't a pairing code") }
                code = read
            } else {
                code = .make()
            }
            let peer = Peer(address: address, port: port, code: code, mayPlant: mayPlant)
            store.peers.append(peer)
            store.ledger.add(recipient: peer.recipient)
            try saveNow()
            restartListener()
            log.notice("pinned the peer at \(address, privacy: .public)")
            return text == nil ? code.text : nil
        }
    }

    /// Unpins the peer at `address`. Decoys it armed stay until root here retires them.
    public func removePeer(address: String) throws {
        try queue.sync {
            guard let peer = store.peers.first(where: { PeerTLS.same($0.address, address) }) else {
                throw Refusal("no peer has that address")
            }
            store.peers.removeAll { $0.id == peer.id }
            store.ledger.remove(recipient: peer.recipient)
            links[peer.id]?.close()
            try saveNow()
            restartListener()
            log.notice("unpinned the peer at \(address, privacy: .public)")
        }
    }

    static func isAddress(_ text: String) -> Bool { IPv4Address(text) != nil || IPv6Address(text) != nil }

    func peer(_ id: UUID) -> Peer? { store.peers.first { $0.id == id } }

    func updatePeer(_ id: UUID, _ change: (inout Peer) -> Void) {
        guard let index = store.peers.firstIndex(where: { $0.id == id }) else { return }
        change(&store.peers[index])
        dirty = true
    }

    // MARK: Connections

    func startPeers() {
        restartListener()
    }

    /// Listens on the pinned address with every peer's key, or not at all.
    /// A listener that fails (its address gone) is tried again.
    func restartListener() {
        listener?.cancel()
        listener = nil
        guard let listen = store.listen, !store.peers.isEmpty, let port = NWEndpoint.Port(rawValue: listen.port) else { return }
        let parameters = PeerTLS.parameters(store.peers.map(\.code))
        parameters.requiredLocalEndpoint = .hostPort(host: NWEndpoint.Host(listen.address), port: port)
        parameters.allowLocalEndpointReuse = true
        guard let listener = try? NWListener(using: parameters) else {
            queue.asyncAfter(deadline: .now() + 30) { [weak self] in if self?.listener == nil { self?.restartListener() } }
            return
        }
        listener.newConnectionHandler = { [weak self] in self?.accepted($0) }
        listener.stateUpdateHandler = { [weak self, weak listener] state in
            guard case .failed = state, let self, let listener, self.listener === listener else { return }
            self.log.error("the peer listener failed; trying again in 30 s")
            self.listener = nil
            self.queue.asyncAfter(deadline: .now() + 30) { [weak self] in if self?.listener == nil { self?.restartListener() } }
        }
        listener.start(queue: queue)
        self.listener = listener
    }

    /// A connection to the listener: refused unless it comes from a pinned
    /// address with none other from there unproven, and closed unless its
    /// first frame proves that peer's key within 5 seconds.
    func accepted(_ connection: NWConnection) {
        guard let host = PeerTLS.host(connection.endpoint), let peer = store.peers.first(where: { PeerTLS.same($0.address, host) }),
              unproven[peer.address] == nil else {
            connection.cancel()
            return
        }
        let id = peer.id, address = peer.address
        let link = PeerLink(connection)
        unproven[address] = link
        link.onClose = { [weak self, weak link] in
            if let self, let link, self.unproven[address] === link { self.unproven[address] = nil }
        }
        link.onProof = { [weak self, weak link] proof in
            guard let self, let link, self.unproven[address] === link else { return }
            self.unproven[address] = nil
            guard let peer = self.peer(id), PeerTLS.verify(proof, link.connection, key: peer.key) else {
                self.log.error("a connection from the peer at \(address, privacy: .public) didn't prove its key")
                link.close()
                return
            }
            self.established(id, link)
        }
        connection.stateUpdateHandler = { [weak link] state in
            switch state {
            case .ready: link?.receive()
            case .failed, .cancelled: link?.close()
            default: break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + Self.proofWait) { [weak self, weak link] in
            if let self, let link, self.unproven[address] === link { link.close() }
        }
    }

    /// Dials a peer pinned with a port, unless already connected or dialing.
    func dial(_ id: UUID) {
        guard let peer = peer(id), let port = peer.port.flatMap({ NWEndpoint.Port(rawValue: $0) }), links[id] == nil,
              dialing[id] == nil else { return }
        let connection = NWConnection(host: NWEndpoint.Host(peer.address), port: port, using: PeerTLS.parameters([peer.code]))
        let link = PeerLink(connection)
        dialing[id] = link
        link.onClose = { [weak self, weak link] in
            guard let self, let link, self.dialing[id] === link else { return }
            self.lost(id, nil)
        }
        connection.stateUpdateHandler = { [weak self, weak link] state in
            guard let self, let link else { return }
            switch state {
            case .ready:
                guard let peer = self.peer(id), let proof = PeerTLS.proof(connection, key: peer.key) else {
                    link.close()
                    return
                }
                link.sendProof(proof)
                self.established(id, link)
                link.receive()
            case .waiting, .failed, .cancelled:
                link.close()
            default: break
            }
        }
        connection.start(queue: queue)
    }

    /// A proven connection: it replaces any older one, sends this watcher's
    /// health first (so the peer knows who it is before any update), then
    /// what the peer hasn't acked.
    func established(_ id: UUID, _ link: PeerLink) {
        if let old = links[id], old !== link { old.close() }
        links[id] = link
        if dialing[id] === link { dialing[id] = nil }
        inFlight[id] = nil
        backoff[id] = nil
        link.onMessage = { [weak self, weak link] message in
            guard let self, let link, self.links[id] === link else { return }
            self.handle(message, from: id, link)
        }
        link.onClose = { [weak self, weak link] in self?.lost(id, link) }
        log.notice("connected to the peer at \(self.peer(id)?.address ?? "?", privacy: .public)")
        link.send(.health(health()))
        deliver(to: id)
    }

    /// A connection ended; a peer this watcher dials is dialed again after a
    /// backoff that doubles to a minute.
    func lost(_ id: UUID, _ link: PeerLink?) {
        if let link {
            guard links[id] === link else { return }
            links[id] = nil
            inFlight[id] = nil
        } else {
            dialing[id] = nil
        }
        guard peer(id)?.port != nil, links[id] == nil else { return }
        let wait = min((backoff[id] ?? 0.5) * 2, Self.maxBackoff)
        backoff[id] = wait
        queue.asyncAfter(deadline: .now() + wait) { [weak self] in self?.dial(id) }
    }

    // MARK: Messages

    func handle(_ message: PeerMessage, from id: UUID, _ link: PeerLink) {
        guard let peer = peer(id) else { return link.close() }
        switch message {
        case .health(let health):
            // A peer is one watcher: never this one, never another peer, never another later.
            guard health.watcher != store.book.watcher,
                  !store.peers.contains(where: { $0.id != id && $0.watcher == health.watcher }),
                  peer.watcher == nil || peer.watcher == health.watcher else {
                log.error("the peer at \(peer.address, privacy: .public) claims another watcher's id; re-pin it if that's right")
                return link.close()
            }
            heard(id, health)
        case .updates(let entries):
            // A peer sends only its own updates; anything else ends the connection.
            guard let watcher = peer.watcher, let last = entries.last, entries.allSatisfy({ $0.update.watcher == watcher }) else {
                return link.close()
            }
            for entry in entries where store.ledger.accept(entry.update, fromPeer: true) {
                if case .alarm(let alarm) = entry.update {
                    log.error("the peer at \(peer.address, privacy: .public) raised its alarm \(alarm.sequence, privacy: .public)")
                }
            }
            // Stored before acked: the ack releases the sender's copy.
            guard (try? saveNow()) != nil else { return link.close() }
            link.send(.ack(last.stamp))
        case .ack(let stamp):
            // Only the batch in flight is acked; anything else ends the connection.
            guard inFlight[id] == stamp else { return link.close() }
            store.ledger.ack(peer.recipient, through: stamp)
            inFlight[id] = nil
            dirty = true
            deliver(to: id)
        case .stopping:
            updatePeer(id) { $0.stopping = true }
        case .plant(let request, let account, let key):
            // A retry of what this peer armed already, whose answer was lost, is done.
            link.send(.answer(request: request, refusal: granted(peer) { try armOnce(account: account, keyLine: key, by: id) }))
        case .retire(let request, let account):
            link.send(.answer(request: request, refusal: granted(peer) {
                // A retry of a retirement already done is done, once that is saved.
                guard store.decoys.contains(where: { $0.account == account }) else { return try saveNow() }
                try retire(account: account, by: id)
            }))
        case .answer(let request, let refusal):
            // Only the peer asked answers.
            guard answers[request]?.peer == id else { return }
            answers.removeValue(forKey: request)?.reply(refusal)
        }
    }

    /// Runs `change` under the planting grant: refused unless root here let
    /// this peer plant, and then only a few decoys of its own.
    private func granted(_ peer: Peer, _ change: () throws -> Void) -> String? {
        guard peer.mayPlant else { return "this watcher doesn't let that peer plant" }
        do {
            try change()
            return nil
        } catch {
            return "\(error)"
        }
    }

    /// A peer's health: heard now, and alarms on its recovery, or its
    /// coverage or delivery changing, one per spell.
    func heard(_ id: UUID, _ health: Health) {
        updatePeer(id) { peer in
            peer.watcher = health.watcher
            peer.lastHealth = Date()
            peer.health = health
            peer.stopping = false
        }
        guard let peer = peer(id) else { return }
        if peer.silent {
            updatePeer(id) { $0.silent = false }
            raise(about: peer, .back)
        }
        if health.coverage == .degraded, !peer.degraded {
            updatePeer(id) { $0.degraded = true }
            raise(about: peer, .degraded)
        } else if health.coverage != .degraded, peer.degraded {
            updatePeer(id) { $0.degraded = false }
            raise(about: peer, .covered)
        }
        if health.delivering == false, !peer.undelivered {
            updatePeer(id) { $0.undelivered = true }
            raise(about: peer, .undelivered)
        } else if health.delivering != false, peer.undelivered {
            updatePeer(id) { $0.undelivered = false }
            raise(about: peer, .delivering)
        }
    }

    func raise(about peer: Peer, _ change: PeerChange) {
        store.book.peer(peer.watcher, address: peer.address, change, at: Date()).forEach(raise)
    }

    /// Each second: health to every connected peer each minute, a silence
    /// alarm for a peer unheard for 5 minutes (counted from this watcher's
    /// own start or stall too, so its own downtime isn't the peer's silence), and
    /// dialing whoever isn't connected.
    func watchPeers(now: Date) {
        for peer in store.peers where !peer.silent {
            let heard = max(peer.lastHealth ?? peer.pinned, awake)
            guard now.timeIntervalSince(heard) >= Self.silentAfter else { continue }
            updatePeer(peer.id) { $0.silent = true }
            raise(about: peer, peer.stopping ? .stopped : .silent)
        }
        if now >= nextHealth, !links.isEmpty {
            nextHealth = now.addingTimeInterval(Self.healthEvery)
            let health = health()
            for link in links.values { link.send(.health(health)) }
        }
        for peer in store.peers where peer.port != nil && links[peer.id] == nil && dialing[peer.id] == nil
            && backoff[peer.id] == nil {
            dial(peer.id)
        }
    }

    func health() -> Health {
        healthSequence += 1
        return Health(watcher: store.book.watcher, instance: "\(boot) \(started.timeIntervalSince1970)", sequence: healthSequence,
                      coverage: coverage, lastSelfTest: store.lastSelfTest, kinds: kinds,
                      latestAlarm: store.book.alarmSequence, delivering: delivering())
    }

    // MARK: Delivery

    func deliver() {
        for id in links.keys { deliver(to: id) }
    }

    /// Sends a peer the next batch of this watcher's own updates it hasn't
    /// acked, one batch at a time, and only what the store has saved.
    func deliver(to id: UUID) {
        guard let link = links[id], inFlight[id] == nil, let peer = peer(id) else { return }
        let pending = store.ledger.pending(for: peer.recipient, from: store.book.watcher).filter { $0.stamp <= savedThrough }
        var batch = Array(pending.prefix(Self.batch))
        while batch.count > 1, FrameReader.frame(.updates(batch)) == nil { batch.removeLast(batch.count / 2) }
        guard let last = batch.last, FrameReader.frame(.updates(batch)) != nil else { return }
        inFlight[id] = last.stamp
        link.send(.updates(batch))
    }

    func peerStatuses() -> [PeerStatus] {
        store.peers.map { peer in
            PeerStatus(address: peer.address, watcher: peer.watcher, connected: links[peer.id] != nil, lastHealth: peer.lastHealth,
                       coverage: peer.health?.coverage, silent: peer.silent, mayPlant: peer.mayPlant,
                       unacked: store.ledger.pending(for: peer.recipient, from: store.book.watcher).count,
                       latestAlarm: peer.health?.latestAlarm, alarmsTaken: peer.watcher.map(store.ledger.lastAlarm) ?? 0)
        }
    }

    /// Saves now, or throws.
    func saveNow() throws {
        dirty = true
        try store.save(state)
        dirty = false
        savedThrough = store.ledger.lastStamp
    }
}

@testable import BufoKit
import BufoContract
import Foundation
import Network
import Testing

struct FrameTests {
    let health = Health(watcher: UUID(), instance: "boot start", sequence: 1, coverage: .full, lastSelfTest: nil,
                        kinds: [.sshKey], latestAlarm: 3, delivering: true)

    @Test func framesSurviveAnySplit() throws {
        let wire = try #require(FrameReader.frame(.health(health))) + #require(FrameReader.frame(.ack(7)))
        for cut in 1..<wire.count {
            var reader = FrameReader()
            let bodies = try reader.take(wire.prefix(cut)) + reader.take(wire.dropFirst(cut))
            #expect(try bodies.map(FrameReader.message) == [.health(health), .ack(7)])
        }
    }

    @Test func oversizedEmptyAndMalformedFramesEndTheConnection() {
        var reader = FrameReader()
        #expect(throws: FrameReader.Failure.oversized) { try reader.take(Data([0, 1, 0, 1])) }
        reader = FrameReader()
        #expect(throws: FrameReader.Failure.oversized) { try reader.take(Data([0, 0, 0, 0])) }
        reader = FrameReader()
        #expect(throws: FrameReader.Failure.malformed) { try reader.take(Data([0, 0, 0, 2]) + Data("{}".utf8)).map(FrameReader.message) }
        #expect(FrameReader.frame(.updates(Array(repeating: Ledger.Entry(stamp: 1, update: .alarm(Alarm(
            watcher: UUID(), sequence: 1, at: Date(), subject: .heldBack(.observed, count: 1)))), count: 2000))) == nil)
    }

    @Test func pairingCodesRoundTrip() throws {
        let code = PairingCode.make()
        #expect(code.text.count == 64)
        #expect(PairingCode(code.text) == code)
        #expect(PairingCode("  \(code.text)\n") == code)
        #expect(PairingCode("not a code") == nil)
        #expect(PairingCode.make() != code)
    }

    @Test func addressesCompareAsAddresses() {
        #expect(PeerTLS.same("100.64.0.1", "100.64.0.1"))
        #expect(!PeerTLS.same("100.64.0.1", "100.64.0.2"))
        #expect(PeerTLS.same("fd7a:115c:a1e0::1", "fd7a:115c:a1e0:0::1"))
        #expect(PeerTLS.same("fe80::1%utun3", "fe80::1"))
        #expect(!PeerTLS.same("host", "host"))
    }

    @Test func peerAlarmsDrawOnTheHealthBudgetInTheSameSequence() {
        var book = IncidentBook(watcher: UUID())
        let start = Fixture.start
        _ = book.record(decoy: UUID(), kind: .sshKey, source: Source(address: "192.0.2.1"), connection: "a", at: start)
        let silent = book.peer(nil, address: "192.0.2.9", .silent, at: start)
        #expect(silent.map(\.sequence) == [2])
        for minute in 1...12 { _ = book.peer(nil, address: "192.0.2.9", .back, at: start.addingTimeInterval(Double(minute))) }
        #expect(book.alarmSequence == 11)
        // Trips still alarm: health has its own budget.
        let trip = book.record(decoy: UUID(), kind: .sshKey, source: Source(address: "192.0.2.2"), connection: "b",
                               at: start.addingTimeInterval(20))
        #expect(trip.alarms.count == 1)
    }
}

/// The real handshake on loopback: TLS-PSK, the exporter proof, and frames.
struct PeerTLSTests {
    @Test func aDialerProvesTheKeyAndAWrongKeyCannot() throws {
        let right = PairingCode.make()
        #expect(try exchange(listener: right, dialer: right) == .proven)
        #expect(try exchange(listener: right, dialer: PairingCode(identity: right.identity, key: PairingCode.make().key)) == .failed)
        #expect(try exchange(listener: right, dialer: .make()) == .failed)
    }

    enum Outcome: Equatable { case proven, unproven, failed }

    func exchange(listener code: PairingCode, dialer: PairingCode) throws -> Outcome {
        let queue = DispatchQueue(label: "test")
        let done = DispatchSemaphore(value: 0)
        let result = Box()
        let parameters = PeerTLS.parameters([code])
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: .any)
        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { connection in
            let link = PeerLink(connection)
            link.onProof = { proof in
                result.outcome = PeerTLS.verify(proof, connection, key: code.key) ? .proven : .unproven
                done.signal()
            }
            connection.stateUpdateHandler = { if case .ready = $0 { link.receive() } }
            connection.start(queue: queue)
        }
        let ready = DispatchSemaphore(value: 0)
        listener.stateUpdateHandler = { if case .ready = $0 { ready.signal() } }
        listener.start(queue: queue)
        _ = ready.wait(timeout: .now() + 5)
        let connection = NWConnection(host: "127.0.0.1", port: listener.port!, using: PeerTLS.parameters([dialer]))
        let link = PeerLink(connection)
        connection.stateUpdateHandler = { state in
            switch state {
            case .ready: link.sendProof(PeerTLS.proof(connection, key: dialer.key)!)
            case .failed, .waiting:
                result.outcome = .failed
                done.signal()
            default: break
            }
        }
        connection.start(queue: queue)
        let finished = done.wait(timeout: .now() + 10)
        connection.cancel()
        listener.cancel()
        return finished == .success ? result.outcome : .failed
    }

    final class Box: @unchecked Sendable {
        var outcome = Outcome.failed
    }
}

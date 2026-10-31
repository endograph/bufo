@testable import BufoKit
import BufoContract
import Foundation
import Security
import Testing

struct HostTests {
    @Test func aHostReportsOnlyWhatItRegisteredAndOnlyAFew() throws {
        var host = PinnedHost(name: "app", requirement: "anchor apple", user: 501)
        let id = UUID()
        #expect(throws: Refusal("that isn't a decoy this host registered")) { try host.decoy(id) }
        try host.register(id)
        try host.register(id)
        #expect(host.registered.count == 1)
        #expect(try host.decoy(id) == (try host.decoy(id)))
        for _ in 1..<PinnedHost.maxRegistered { try host.register(UUID()) }
        #expect(throws: Refusal("this host has registered 16 decoys already")) { try host.register(UUID()) }
    }

    @Test func aCommentCantReachPastItsParentheses() throws {
        func compiles(_ text: String) -> Bool {
            var compiled: SecRequirement?
            return SecRequirementCreateWithString(text as CFString, [], &compiled) == errSecSuccess
        }
        let commented = "anchor apple // the rest is a comment"
        #expect(compiles(commented))
        #expect(!compiles(Service.either("identifier bufo", [commented])))
        #expect(compiles(Service.either("identifier bufo", [try PinnedHost.canonical(commented)])))
        #expect(throws: Refusal("that code-signing requirement doesn't compile")) { try PinnedHost.canonical("not a requirement") }
    }

    @Test func twoHostsIdsNeverMeet() throws {
        var first = PinnedHost(name: "first", requirement: "", user: 501), second = PinnedHost(name: "second", requirement: "", user: 501)
        let id = UUID()
        try first.register(id)
        try second.register(id)
        #expect(try first.decoy(id) != (try second.decoy(id)))
        #expect(try first.decoy(id) != id)
    }

    @Test func aHostsCursorIsItsOwn() {
        var ledger = Ledger()
        ledger.add(recipient: "host app")
        ledger.add(recipient: "peer x")
        let watcher = UUID()
        for sequence in 1...3 as ClosedRange<UInt64> {
            ledger.accept(.alarm(Alarm(watcher: watcher, sequence: sequence, at: Date(), subject: .heldBack(.observed, count: 1))))
        }
        ledger.ack("host app", through: 2)
        #expect(ledger.pending(for: "host app").map(\.stamp) == [3])
        #expect(ledger.pending(for: "peer x").count == 3)
    }

    @Test func deliveryIsDownOnlyWhenEveryHostThatTakesUpdatesStopped() {
        let now = Date()
        var reporter = PinnedHost(name: "core", requirement: "anchor apple", user: 501)
        var taker = PinnedHost(name: "commander", requirement: "anchor apple", user: 501)
        let long = now.addingTimeInterval(-3600)
        // A host that only reports, or none, takes nothing to deliver.
        #expect(Watcher.delivering([], awake: long, now: now) == nil)
        #expect(Watcher.delivering([reporter], awake: long, now: now) == nil)
        taker.lastSeen = now.addingTimeInterval(-60)
        #expect(Watcher.delivering([reporter, taker], awake: long, now: now) == true)
        taker.lastStage = .failed
        #expect(Watcher.delivering([reporter, taker], awake: long, now: now) == false)
        taker.lastStage = .accepted
        taker.lastSeen = now.addingTimeInterval(-1000)
        #expect(Watcher.delivering([taker], awake: long, now: now) == false)
        // This watcher's own downtime isn't its hosts' quiet.
        #expect(Watcher.delivering([taker], awake: now.addingTimeInterval(-60), now: now) == true)
        reporter.lastSeen = now
        #expect(Watcher.delivering([reporter, taker], awake: long, now: now) == true)
    }
}

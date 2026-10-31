import BufoContract
import BufoKit
import Foundation
import Testing

struct ContractTests {
    @Test func notInstalledIsOneField() throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        #expect(String(decoding: try encoder.encode(Status.notInstalled), as: UTF8.self) == #"{"installed":false}"#)
    }

    @Test func statusRoundTrips() throws {
        let status = Status(installed: true, watcher: UUID(), version: 12, kinds: [.sshKey], coverage: .degraded,
                            openIncidents: [.sshKey: 2], notes: ["store unencrypted until v1"])
        let json = try JSONEncoder().encode(status)
        #expect(try JSONDecoder().decode(Status.self, from: json) == status)
        // Kinds are keys, as a host reading the JSON expects.
        #expect(String(decoding: json, as: UTF8.self).contains(#""openIncidents":{"ssh-key":2}"#))
    }

    @Test func noContractTypeCarriesAPlacement() throws {
        // What leaves the watcher names the kind and source, never the account or fingerprint.
        var book = IncidentBook(watcher: UUID())
        let (incident, alarms) = book.record(decoy: Fixture.decoy.id, kind: .sshKey, source: Source(address: "192.0.2.10"),
                                             connection: "1", at: Fixture.start)
        let updates = [Update.incident(incident)] + alarms.map(Update.alarm)
        let json = String(decoding: try JSONEncoder().encode(updates), as: UTF8.self)
        #expect(!json.contains(Fixture.decoy.account))
        #expect(!json.contains("SHA256"))
    }

    @Test func installConfigIsTrustedOnlyWhenRootsAlone() throws {
        let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }
        let binary = dir.appendingPathComponent("watch")
        #expect(InstallConfig.find(beside: binary) == .notInstalled)
        try JSONEncoder().encode(InstallConfig(label: "l", service: "s", state: "/nowhere")).write(to: InstallConfig.url(beside: binary))
        // Written by this (non-root) test, so it isn't root's.
        guard case .refused = InstallConfig.find(beside: binary) else { Issue.record("trusted a config root doesn't own"); return }
    }

    @Test func aDirectoryIsRootsAloneOnlyAllTheWayUp() throws {
        #expect(try rootsAloneDirectory("/usr/bin") == "/usr/bin")
        // Through a link root made, to where root alone can write.
        #expect(try rootsAloneDirectory("/var/db") == "/private/var/db")
        #expect(throws: Refusal.self) { try rootsAloneDirectory(FileManager.default.temporaryDirectory.path) }
        #expect(throws: Refusal.self) { try rootsAloneDirectory("/nonexistent-\(UUID().uuidString)") }
    }

    @Test func installRefusesWithoutRoot() {
        #expect(throws: Refusal.self) {
            try Installer.install(artifact: "/bin/ls", binary: "/usr/local/x/y", label: "l", service: "s", state: "/var/db/z")
        }
    }
}

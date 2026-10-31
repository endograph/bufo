import BufoKit
import Foundation
import Testing

struct SSHLineTests {
    @Test func readsEachDecoyLine() {
        let lines = Fixture.decoyUse.map { SSHLine.parse($0.0) }
        #expect(lines[0] == .connection(address: "192.0.2.10", port: 57740))
        #expect(lines[1] == .keyFound(fingerprint: Fixture.decoyFingerprint, file: "/private/var/home/builder/.ssh/authorized_keys"))
        #expect(lines[2] == .postponed(user: "builder", address: "192.0.2.10", port: 57740))
        #expect(lines[4] == .publickey(accepted: false, user: "builder", address: "192.0.2.10", port: 57740,
                                       fingerprint: Fixture.decoyFingerprint))
        #expect(lines[5] == .deniedByPAM(user: "builder"))
    }

    @Test func readsInvalidUsers() {
        #expect(SSHLine.parse("Invalid user nosuch from 192.0.2.10 port 57750") == .invalidUser(user: "nosuch", address: "192.0.2.10", port: 57750))
    }

    @Test func readsTheAccountFromTheRight() {
        // An account name holding sshd's own words can't move the address or fingerprint.
        let line = "Failed publickey for a from 198.51.100.1 port 1 ssh2: ED25519 \(Fixture.decoyFingerprint) from 192.0.2.10 port 2 ssh2: ED25519 \(Fixture.otherFingerprint)"
        #expect(SSHLine.parse(line) == .publickey(accepted: false,
                                                  user: "a from 198.51.100.1 port 1 ssh2: ED25519 \(Fixture.decoyFingerprint)",
                                                  address: "192.0.2.10", port: 2, fingerprint: Fixture.otherFingerprint))
    }

    @Test func ignoresAnythingElse() {
        for message in [
            "Accepted publickey for builder from 192.0.2.10 port 57740 ssh2: ED25519 SHA256:short",
            "Postponed publickey for builder from 192.0.2.10 port 57740 ssh2 [preauth] trailing",
            "prefix Failed publickey for builder from 192.0.2.10 port 1 ssh2: ED25519 \(Fixture.decoyFingerprint)",
            "Failed publickey for builder\nfrom 192.0.2.10 port 1 ssh2: ED25519 \(Fixture.decoyFingerprint)",
            "Connection closed by authenticating user builder 192.0.2.10 port 64580 [preauth]",
            "in pam_sm_acct_mgmt(): pam_sacl: denying 'builder' due to failed service ACL check",
            String(repeating: "x", count: 501),
        ] {
            #expect(SSHLine.parse(message) == nil)
        }
    }

    @Test func admitsOnlyTheSystemSSHD() {
        let real = Fixture.event(Fixture.decoyUse[4].0)
        #expect(Fixture.sshd.admits(real, accountUIDs: [400]))
        // A program called sshd-session elsewhere logs the same text under its own path, UUID, and user.
        #expect(!Fixture.sshd.admits(Fixture.event(real.eventMessage, uid: 501, path: "/Users/owner/sshd-session",
                                                   imageUUID: "F11E6B98-8A05-30E5-8443-21EC4BEFE047"), accountUIDs: [400]))
        #expect(!Fixture.sshd.admits(Fixture.event(real.eventMessage, imageUUID: "F11E6B98-8A05-30E5-8443-21EC4BEFE047"),
                                     accountUIDs: [400]))
        #expect(!Fixture.sshd.admits(Fixture.event(real.eventMessage, uid: 501), accountUIDs: [400]))
        #expect(Fixture.sshd.admits(Fixture.event(Fixture.decoyUse[1].0, uid: 400), accountUIDs: [400]))
    }

    @Test func decodesTheStreamsNDJSON() throws {
        let line = #"{"timezoneName": "", "messageType": "Info", "eventType": "logEvent", "userID": 0, "processImagePath": "/usr/libexec/sshd-session", "senderImagePath": "/usr/libexec/sshd-session", "timestamp": "2026-10-29 13:22:25.465043-0700", "eventMessage": "Connection closed by authenticating user nobody 192.0.2.10 port 64580 [preauth]", "processImageUUID": "9A2854EC-AB00-3F86-9F2E-FDD69E37A165", "processID": 54351, "bootUUID": "3B1C2F44-5D0E-4A1B-9C77-0E2D6A1F8B10", "machTimestamp": 114764742407}"#
        let event = try #require(LogEvent.decode(line: Data(line.utf8)))
        #expect(event.processID == 54351)
        #expect(event.userID == 0)
        #expect(event.machTimestamp == 114_764_742_407)
        #expect(abs(event.timestamp.timeIntervalSince1970 - 1_793_305_345.465043) < 0.000_001)
        #expect(LogEvent.decode(line: Data("Filtering the log data using …".utf8)) == nil)
    }
}

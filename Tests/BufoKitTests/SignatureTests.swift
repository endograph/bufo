import BufoKit
import Foundation
import Testing

struct SignatureTests {
    static let signed = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent()
        .deletingLastPathComponent().appendingPathComponent(".build/bufo-signed/bufo").path

    @Test(.enabled(if: FileManager.default.fileExists(atPath: signed), "make build first"))
    func theSignedBuildPassesItsOwnCheck() throws {
        let signature = try Signature.check(Self.signed)
        #expect(signature.version > 0)
        #expect(try Signature.check(Self.signed, requirement: signature.requirement) == signature)
        var other = signature
        other.identifier += "-other"
        #expect(throws: Refusal.self) { try Signature.check(Self.signed, requirement: other.requirement) }
    }

    @Test(.enabled(if: FileManager.default.fileExists(atPath: signed), "make build first"))
    func aChangedCopyIsRefused() throws {
        let copy = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString).path
        var data = try Data(contentsOf: URL(fileURLWithPath: Self.signed))
        data[data.count / 2] ^= 0xFF
        try data.write(to: URL(fileURLWithPath: copy))
        defer { try? FileManager.default.removeItem(atPath: copy) }
        #expect(throws: Refusal.self) { try Signature.check(copy) }
    }

    @Test func theSystemsOwnToolsAreNotBufo() {
        #expect(throws: Refusal.self) { try Signature.check("/bin/ls") }
    }
}

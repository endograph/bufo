import Foundation
import Security

/// What Bufo pins about a build of itself (PLAN.md, Root file handling): the
/// team and identifier its signature names, and the version it embeds.
public struct Signature: Equatable, Sendable {
    public var team: String
    public var identifier: String
    /// `CFBundleVersion` in the embedded Info.plist; it only grows.
    public var version: Int

    /// The code-signing requirement for any build of this team and identifier.
    public var requirement: String {
        "anchor apple generic and certificate leaf[subject.OU] = \"\(team)\" and identifier \"\(identifier)\""
    }

    /// Reads and checks the code at `path`: a strictly valid signature on
    /// every architecture, satisfying `requirement` when one is given, with
    /// the hardened runtime, no entitlements, and a version.
    public static func check(_ path: String, requirement: String? = nil) throws -> Signature {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(URL(fileURLWithPath: path) as CFURL, [], &code) == errSecSuccess, let code else {
            throw Refusal("\(path) isn't code")
        }
        return try check(code, path, requirement: requirement)
    }

    /// The running executable's own, read from the very object the system
    /// then holds to the running code, which fails if the file on disk is no
    /// longer what runs: a file swapped after launch can't name the team.
    public static func ofSelf() throws -> Signature {
        var running: SecCode?
        var disk: SecStaticCode?
        guard SecCodeCopySelf([], &running) == errSecSuccess, let running,
              SecCodeCopyStaticCode(running, [], &disk) == errSecSuccess, let disk else {
            throw Refusal("this binary can't read its own signature")
        }
        let me = try check(disk, Bundle.main.executablePath ?? "this binary", requirement: nil)
        var compiled: SecRequirement?
        guard SecRequirementCreateWithString(me.requirement as CFString, [], &compiled) == errSecSuccess,
              SecCodeCheckValidity(running, [], compiled) == errSecSuccess else {
            throw Refusal("this binary's file isn't the code running")
        }
        return me
    }

    static func check(_ code: SecStaticCode, _ path: String, requirement: String?) throws -> Signature {
        var compiled: SecRequirement?
        if let requirement, SecRequirementCreateWithString(requirement as CFString, [], &compiled) != errSecSuccess {
            throw Refusal("the requirement doesn't compile")
        }
        let flags = SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        let status = SecStaticCodeCheckValidity(code, flags, compiled)
        guard status == errSecSuccess else {
            throw Refusal("\(path) isn't validly signed\(requirement == nil ? "" : " by this build's team and identifier") (\(status))")
        }
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation),
                                            &info) == errSecSuccess,
              let info = info as? [String: Any],
              let team = info[kSecCodeInfoTeamIdentifier as String] as? String,
              let identifier = info[kSecCodeInfoIdentifier as String] as? String else {
            throw Refusal("\(path) has no team or identifier")
        }
        // Both go into a requirement's text, so nothing that could end a quoted string.
        guard team.wholeMatch(of: /[A-Z0-9]{10}/) != nil, identifier.wholeMatch(of: /[A-Za-z0-9][A-Za-z0-9._-]*/) != nil else {
            throw Refusal("\(path) has a team or identifier Bufo won't pin")
        }
        let codeFlags = (info[kSecCodeInfoFlags as String] as? NSNumber)?.uint32Value ?? 0
        guard codeFlags & SecCodeSignatureFlags.runtime.rawValue != 0 else { throw Refusal("\(path) lacks the hardened runtime") }
        if let entitlements = info[kSecCodeInfoEntitlementsDict as String] as? [String: Any], !entitlements.isEmpty {
            throw Refusal("\(path) carries entitlements: \(entitlements.keys.sorted().joined(separator: ", "))")
        }
        guard let plist = info[kSecCodeInfoPList as String] as? [String: Any],
              let version = (plist["CFBundleVersion"] as? String).flatMap(Int.init) else {
            throw Refusal("\(path) has no version")
        }
        return Signature(team: team, identifier: identifier, version: version)
    }
}

/// Why Bufo won't do something, in words for the owner.
public struct Refusal: Error, CustomStringConvertible, Equatable {
    public var description: String
    public init(_ description: String) { self.description = description }
}

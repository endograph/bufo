import BufoContract
import Foundation
import Security
import XPC

/// The daemon's Mach service (PLAN.md, The local transport): both ends pin
/// a code-signing requirement, checked before anything is read. A request
/// is a dictionary of strings naming it in `request`; a reply carries JSON
/// in `reply`, or words in `error`. The client is `BufoService`, which
/// hosts link from the contract.
public enum Service {
    /// Who sent a request: Bufo's own CLI, as root or not, or a pinned host,
    /// by its pinning's id.
    public enum Caller: Sendable, Equatable {
        case bufo(root: Bool)
        case host(UUID)
    }

    /// A pinned host: its code-signing requirement and the local user it runs as.
    public struct HostIdentity: Sendable {
        public var id: UUID
        public var requirement: String
        public var user: uid_t
    }

    public typealias Handler = @Sendable (_ request: [String: String], _ caller: Caller) throws -> Data

    /// Serves `name` to callers that satisfy `requirement` (Bufo's own) or
    /// a pinned host's. Each message is matched to its caller by its code
    /// signature and user against the hosts pinned when it arrives, before it
    /// is read, so a host unpinned since its connection opened is refused.
    /// Never returns.
    public static func serve(_ name: String, requirement: String, hosts: @escaping @Sendable () -> [HostIdentity],
                             handler: @escaping Handler) -> Never {
        let listener = xpc_connection_create_mach_service(name, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_LISTENER))
        xpc_connection_set_event_handler(listener) { peer in
            guard xpc_get_type(peer) == XPC_TYPE_CONNECTION else { return }
            // The setter takes one requirement per connection: Bufo's or any host's.
            guard xpc_connection_set_peer_code_signing_requirement(peer, either(requirement, hosts().map(\.requirement))) == 0 else {
                xpc_connection_cancel(peer)
                return
            }
            xpc_connection_set_event_handler(peer) { message in
                // A caller that fails the requirement arrives here as an error, never as a message.
                guard xpc_get_type(message) == XPC_TYPE_DICTIONARY, let reply = xpc_dictionary_create_reply(message),
                      let remote = xpc_dictionary_get_remote_connection(message) else { return }
                do {
                    guard let caller = caller(message, euid: xpc_connection_get_euid(remote), requirement: requirement, hosts: hosts()) else {
                        throw Refusal("this app isn't pinned here as a host")
                    }
                    var request: [String: String] = [:]
                    xpc_dictionary_apply(message) { key, value in
                        if xpc_get_type(value) == XPC_TYPE_STRING, let string = xpc_string_get_string_ptr(value) {
                            request[String(cString: key)] = String(cString: string)
                        }
                        return true
                    }
                    let data = try handler(request, caller)
                    data.withUnsafeBytes { xpc_dictionary_set_data(reply, "reply", $0.baseAddress!, $0.count) }
                } catch {
                    xpc_dictionary_set_string(reply, "error", "\(error)")
                }
                xpc_connection_send_message(remote, reply)
            }
            xpc_connection_resume(peer)
        }
        xpc_connection_resume(listener)
        dispatchMain()
    }

    /// Which requirement the message's sender satisfies, and, for a host,
    /// whether it runs as that host's user.
    private static func caller(_ message: xpc_object_t, euid: uid_t, requirement: String, hosts: [HostIdentity]) -> Caller? {
        var code: SecCode?
        guard SecCodeCreateWithXPCMessage(message, [], &code) == errSecSuccess, let code else { return nil }
        func satisfies(_ text: String) -> Bool {
            var compiled: SecRequirement?
            guard SecRequirementCreateWithString(text as CFString, [], &compiled) == errSecSuccess, let compiled else { return false }
            return SecCodeCheckValidity(code, [], compiled) == errSecSuccess
        }
        if satisfies(requirement) { return .bufo(root: euid == 0) }
        return hosts.first { $0.user == euid && satisfies($0.requirement) }.map { .host($0.id) }
    }

    /// One requirement any of `requirements` satisfies. Each is canonical
    /// text (`SecRequirementCopyString`), so none can reach past its parentheses.
    public static func either(_ first: String, _ others: [String]) -> String {
        ([first] + others).map { "(\($0))" }.joined(separator: " or ")
    }

    /// Sends `request` to the daemon at `name`, which must satisfy
    /// `requirement`; returns its reply.
    public static func call(_ name: String, requirement: String, _ request: [String: String],
                            timeout: TimeInterval = 5) throws -> Data {
        do {
            return try BufoService(name: name, requirement: requirement).call(request, timeout: timeout)
        } catch let error as BufoError {
            throw Refusal(error.description)
        }
    }

    /// The daemon's status.
    public static func status(_ name: String, requirement: String, timeout: TimeInterval = 5) throws -> Status {
        try JSONDecoder().decode(Status.self, from: call(name, requirement: requirement, ["request": "status"], timeout: timeout))
    }
}

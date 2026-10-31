#if os(macOS)
import Foundation
import XPC

/// Why a call to Bufo failed. A host shows `notInstalled` as Bufo being
/// absent, and anything else as trouble (PLAN.md, The API).
public enum BufoError: Error, CustomStringConvertible, Equatable {
    /// No daemon serves the name.
    case notInstalled
    /// The daemon didn't answer, or isn't the Bufo `requirement` names.
    case unreachable(String)
    /// The daemon answered no, in its words.
    case refused(String)

    public var description: String {
        switch self {
        case .notInstalled: "Bufo isn't installed"
        case .unreachable(let why): "the daemon didn't answer: \(why)"
        case .refused(let why): why
        }
    }
}

/// Bufo's daemon as a host (or Bufo's own CLI) reaches it (PLAN.md, The
/// local transport): its Mach service in the system domain, which must
/// satisfy `requirement` before anything is sent. A request is a dictionary
/// of strings naming it in `request`; a reply is JSON. Both are the host's
/// own settings, since other builds of Bufo carry other teams.
public struct BufoService: Sendable {
    public var name: String
    public var requirement: String

    public init(name: String, requirement: String) {
        self.name = name
        self.requirement = requirement
    }

    public func call(_ request: [String: String], timeout: TimeInterval = 5) throws -> Data {
        let connection = xpc_connection_create_mach_service(name, nil, UInt64(XPC_CONNECTION_MACH_SERVICE_PRIVILEGED))
        guard xpc_connection_set_peer_code_signing_requirement(connection, requirement) == 0 else {
            throw BufoError.unreachable("the requirement doesn't compile")
        }
        xpc_connection_set_event_handler(connection) { _ in }
        xpc_connection_resume(connection)
        defer { xpc_connection_cancel(connection) }
        let message = xpc_dictionary_create(nil, nil, 0)
        for (key, value) in request { xpc_dictionary_set_string(message, key, value) }
        let answer = Answer()
        xpc_connection_send_message_with_reply(connection, message, nil) { reply in
            if xpc_get_type(reply) == XPC_TYPE_DICTIONARY {
                var length = 0
                if let bytes = xpc_dictionary_get_data(reply, "reply", &length) {
                    answer.result = .success(Data(bytes: bytes, count: length))
                } else if let error = xpc_dictionary_get_string(reply, "error") {
                    answer.result = .failure(.refused(String(cString: error)))
                }
            } else if reply === XPC_ERROR_CONNECTION_INVALID {
                answer.result = .failure(.notInstalled)
            } else {
                let why = xpc_dictionary_get_string(reply, XPC_ERROR_KEY_DESCRIPTION).map { String(cString: $0) }
                answer.result = .failure(.unreachable(why ?? "no reply"))
            }
            answer.done.signal()
        }
        guard answer.done.wait(timeout: .now() + timeout) == .success else { throw BufoError.unreachable("no reply in time") }
        return try (answer.result ?? .failure(.unreachable("no reply"))).get()
    }

    public func status() throws -> Status {
        try decode(Status.self, call(["request": "status"]))
    }

    // MARK: A host's calls

    /// What this host hasn't acked, oldest first, at most a batch; with
    /// `wait`, held up to that many seconds (at most 25) for something new.
    public func updates(wait: TimeInterval = 0) throws -> [Stamped] {
        try decode([Stamped].self, call(["request": "updates", "wait": "\(Int(wait))"], timeout: wait + 10))
    }

    /// This host has stored everything through `stamp` durably.
    public func ack(through stamp: UInt64) throws {
        _ = try call(["request": "ack", "through": "\(stamp)"])
    }

    /// How far this host got an alarm. Bufo keeps each host's latest stage.
    public func delivery(_ stage: DeliveryStage, of alarm: Alarm) throws {
        _ = try call(["request": "delivery", "stage": stage.rawValue, "watcher": alarm.watcher.uuidString,
                      "sequence": "\(alarm.sequence)"])
    }

    /// Registers one of this host's own decoys (its host credential) by an
    /// id it chooses; ids are this host's alone, and a few at most.
    public func register(_ decoy: UUID) throws {
        _ = try call(["request": "register", "decoy": decoy.uuidString])
    }

    /// Reports that a decoy this host registered was presented, from
    /// `source` (an address, or the name the host has for it).
    public func presented(_ decoy: UUID, source: String) throws {
        _ = try call(["request": "presented", "decoy": decoy.uuidString, "source": source])
    }

    private func decode<T: Decodable>(_ type: T.Type, _ data: Data) throws -> T {
        do { return try JSONDecoder().decode(type, from: data) } catch { throw BufoError.unreachable("the reply didn't read") }
    }

    private final class Answer: @unchecked Sendable {
        let done = DispatchSemaphore(value: 0)
        var result: Result<Data, BufoError>?
    }
}
#endif

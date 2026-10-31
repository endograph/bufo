import BufoContract
import Foundation

// A host for drills (PLAN.md, Milestone 1, step 7), linking only the contract
// as a real host does. `follow` stores each batch of updates in a file,
// synced, before it acks, so a host killed at any point loses nothing.

let usage = """
    usage: bufo-testhost --service <name> --requirement <Bufo's code requirement> <command>
      status
      register <decoy id>
      present <decoy id> <source>
      follow <file> <seconds>    take updates for that long, storing each batch before acking it
      summary <file>             what the file holds: distinct incidents and alarms
    """

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func print<T: Encodable>(json value: T) {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    encoder.dateEncodingStrategy = .iso8601
    FileHandle.standardOutput.write((try! encoder.encode(value)) + Data("\n".utf8))
}

var arguments = Array(CommandLine.arguments.dropFirst())
guard arguments.count >= 5, arguments[0] == "--service", arguments[2] == "--requirement" else { fail(usage) }
let bufo = BufoService(name: arguments[1], requirement: arguments[3])
arguments.removeFirst(4)

func attempt<T>(_ body: () throws -> T) -> T {
    do { return try body() } catch { fail("\(error)") }
}

/// Every update the file holds, one JSON line each.
func held(_ path: String) -> [Stamped] {
    let text = (try? String(contentsOfFile: path, encoding: .utf8)) ?? ""
    return text.split(separator: "\n").compactMap { try? JSONDecoder().decode(Stamped.self, from: Data($0.utf8)) }
}

struct Summary: Encodable {
    var updates: Int
    var incidents: Int
    var alarms: Int
    var lastStamp: UInt64
}

func summary(_ path: String) -> Summary {
    let all = held(path)
    var incidents = Set<UUID>(), alarms = Set<String>()
    for entry in all {
        switch entry.update {
        case .incident(let incident): incidents.insert(incident.id)
        case .alarm(let alarm): alarms.insert("\(alarm.watcher) \(alarm.sequence)")
        }
    }
    return Summary(updates: all.count, incidents: incidents.count, alarms: alarms.count, lastStamp: all.map(\.stamp).max() ?? 0)
}

switch arguments.first {
case "status" where arguments.count == 1:
    print(json: attempt { try bufo.status() })
case "register" where arguments.count == 2:
    guard let id = UUID(uuidString: arguments[1]) else { fail(usage) }
    attempt { try bufo.register(id) }
    print(json: ["registered": id.uuidString])
case "present" where arguments.count == 3:
    guard let id = UUID(uuidString: arguments[1]) else { fail(usage) }
    attempt { try bufo.presented(id, source: arguments[2]) }
    print(json: ["reported": id.uuidString])
case "follow" where arguments.count == 3:
    guard let seconds = TimeInterval(arguments[2]) else { fail(usage) }
    let path = arguments[1]
    if !FileManager.default.fileExists(atPath: path) { FileManager.default.createFile(atPath: path, contents: nil) }
    guard let file = FileHandle(forWritingAtPath: path) else { fail("\(path) doesn't open") }
    let until = Date().addingTimeInterval(seconds)
    while Date() < until {
        let batch = attempt { try bufo.updates(wait: min(20, max(1, until.timeIntervalSinceNow))) }
        guard let last = batch.last else { continue }
        file.seekToEndOfFile()
        for entry in batch { file.write((try! JSONEncoder().encode(entry)) + Data("\n".utf8)) }
        // Stored, then acked: Bufo releases nothing this host hasn't kept.
        do { try file.synchronize() } catch { fail("\(path) didn't sync: \(error)") }
        attempt { try bufo.ack(through: last.stamp) }
        for entry in batch {
            if case .alarm(let alarm) = entry.update { try? bufo.delivery(.stored, of: alarm) }
        }
    }
    print(json: summary(path))
case "summary" where arguments.count == 2:
    print(json: summary(arguments[1]))
default:
    fail(usage)
}

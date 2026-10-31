import Foundation

/// One log line's identity, so the detector knows where it stopped and the
/// stream and history can be matched line for line. `log stream` and `log
/// show` report a line's timestamp milliseconds apart and its Mach time a
/// few ticks apart at most, and only history names the boot; so a line is
/// its boot, process, and message, at a Mach time within `tolerance`.
public struct LogMark: Codable, Sendable, Equatable {
    public var boot: String
    public var mach: UInt64
    public var processID: Int32
    public var message: String
    /// Its timestamp, which says where history starts.
    public var at: Date

    /// `boot` is this boot's, for a streamed line that names none.
    public init(_ event: LogEvent, boot: String) {
        self.boot = event.bootUUID.isEmpty ? boot : event.bootUUID
        mach = event.machTimestamp
        processID = event.processID
        message = event.eventMessage
        at = event.timestamp
    }

    /// 100 microseconds: two lines alike from one process came 300 apart.
    static let tolerance: UInt64 = {
        var base = mach_timebase_info_data_t()
        mach_timebase_info(&base)
        return base.numer == 0 ? 2_400 : 100_000 * UInt64(base.denom) / UInt64(base.numer)
    }()

    public func matches(_ other: LogMark) -> Bool {
        boot == other.boot && processID == other.processID && message == other.message
            && (mach > other.mach ? mach - other.mach : other.mach - mach) <= Self.tolerance
    }

    /// Whether `other` was logged no later than this line.
    func covers(_ other: LogMark) -> Bool {
        boot == other.boot ? other.mach <= mach + Self.tolerance : other.at <= at
    }
}

/// Lines read back from history, to find one streamed again.
struct LogMarks {
    private var lines: [String: [LogMark]] = [:]

    init(_ marks: [LogMark]) {
        for mark in marks { lines["\(mark.processID) \(mark.message)", default: []].append(mark) }
    }

    func contains(_ mark: LogMark) -> Bool {
        lines["\(mark.processID) \(mark.message)"]?.contains { $0.matches(mark) } ?? false
    }
}

/// sshd's lines from the unified log (PLAN.md, Detection): Apple's `log`
/// tool, streamed live, or shown from history after a gap.
enum SSHDLog {
    static func predicate(_ sshd: SSHDIdentity) -> String { "processImagePath == \"\(sshd.path)\"" }

    /// The events since `start`, oldest first; nil if history can't be read.
    static func history(_ sshd: SSHDIdentity, since start: Date) -> [LogEvent]? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let run = System.run("/usr/bin/log", ["show", "--style", "ndjson", "--info", "--start", formatter.string(from: start),
                                              "--predicate", predicate(sshd)], timeout: 120)
        guard run.status == 0 else { return nil }
        return run.output.split(separator: UInt8(ascii: "\n")).compactMap { LogEvent.decode(line: Data($0)) }
    }

    /// Where a restart picks up: given the last line counted, the history
    /// read back, and what the stream buffered meanwhile (each marked in
    /// `boot`, this boot), the lines that only rebuild which connections were
    /// counted (`replay`), those still to count (`live`), and whether history
    /// reached the last line counted. Lines both read back and streamed
    /// count once.
    static func resume(after last: LogMark?, history: [LogEvent], buffered: [LogEvent], boot: String)
        -> (replay: [LogEvent], live: [LogEvent], reached: Bool) {
        var replay: [LogEvent] = [], live: [LogEvent] = []
        var reached = last == nil
        for event in history {
            let mark = LogMark(event, boot: boot)
            if let last, !reached {
                if last.matches(mark) {
                    reached = true
                    replay.append(event)
                } else if last.covers(mark) {
                    replay.append(event)
                } else {
                    live.append(event)
                }
            } else {
                live.append(event)
            }
        }
        let read = LogMarks(history.map { LogMark($0, boot: boot) })
        live += buffered.filter { !read.contains(LogMark($0, boot: boot)) }
        return (replay, live, reached)
    }
}

/// `log stream` on sshd, one event at a time on `queue`, then `ended` once
/// when it stops for any reason.
final class SSHDStream: @unchecked Sendable {
    private let process = Process()
    private let queue: DispatchQueue
    private var pending = Data()
    private var skipping = false

    init(_ sshd: SSHDIdentity, queue: DispatchQueue, event: @escaping @Sendable (LogEvent) -> Void,
         ended: @escaping @Sendable () -> Void) {
        self.queue = queue
        process.executableURL = URL(fileURLWithPath: "/usr/bin/log")
        process.arguments = ["stream", "--style", "ndjson", "--level", "info", "--predicate", SSHDLog.predicate(sshd)]
        let output = Pipe()
        process.standardOutput = output
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        output.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            guard let self else { return }
            if data.isEmpty {
                handle.readabilityHandler = nil
                return
            }
            let events = self.split(data)
            queue.async { events.forEach(event) }
        }
        process.terminationHandler = { _ in queue.async(execute: ended) }
    }

    func start() throws { try process.run() }

    func stop() { if process.isRunning { process.terminate() } }

    /// Whole lines out of the pipe's chunks; a line longer than any event
    /// is dropped whole rather than held.
    private func split(_ data: Data) -> [LogEvent] {
        pending += data
        var events: [LogEvent] = []
        while let newline = pending.firstIndex(of: UInt8(ascii: "\n")) {
            let line = pending[pending.startIndex..<newline]
            pending = Data(pending[pending.index(after: newline)...])
            if skipping {
                skipping = false
            } else if let event = LogEvent.decode(line: Data(line)) {
                events.append(event)
            }
        }
        if pending.count > LogEvent.maxLine {
            pending = Data()
            skipping = true
        }
        return events
    }
}

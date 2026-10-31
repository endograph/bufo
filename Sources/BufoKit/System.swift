import Foundation

/// Root's primitives for files and tools (PLAN.md, Root file handling). Paths
/// passed here lie below a directory root alone can change.
enum System {
    /// Writes a new file where nothing was, never through a link.
    static func write(_ data: Data, to path: String, mode: mode_t) throws {
        let fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw Refusal("\(path): \(lastError)") }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        do {
            guard fchmod(fd, mode) == 0 else { throw Refusal("\(path): \(lastError)") }
            try file.write(contentsOf: data)
            try file.synchronize()
        } catch {
            unlink(path)
            throw error as? Refusal ?? Refusal("\(path) couldn't be written")
        }
    }

    /// Replaces `path` whole: written beside it, then renamed over it.
    static func replace(_ path: String, with data: Data, mode: mode_t) throws {
        let url = URL(fileURLWithPath: path)
        let beside = url.deletingLastPathComponent().path + "/." + url.lastPathComponent + "." + UUID().uuidString
        try write(data, to: beside, mode: mode)
        guard rename(beside, path) == 0 else {
            unlink(beside)
            throw Refusal("\(path): \(lastError)")
        }
    }

    static func exists(_ path: String) -> Bool {
        var info = stat()
        return lstat(path, &info) == 0
    }

    /// A regular file's contents, read without following a link, if no larger than `limit`.
    static func read(_ path: String, limit: Int = 64 * 1024) -> Data? {
        let fd = open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else { return nil }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_size <= limit else { return nil }
        return try? file.read(upToCount: limit) ?? Data()
    }

    /// Runs a system tool by path, with no shell and nothing on its
    /// standard input; returns its exit status and standard output. A tool
    /// still running after `timeout` is killed and counts as failed, so no
    /// tool can hold the daemon.
    @discardableResult
    static func run(_ tool: String, _ arguments: [String], timeout: TimeInterval = 30) -> (status: Int32, output: Data) {
        let process = Process()
        process.executableURL = URL(fileURLWithPath: tool)
        process.arguments = arguments
        let pipe = Pipe()
        process.standardOutput = pipe
        process.standardError = FileHandle.nullDevice
        process.standardInput = FileHandle.nullDevice
        let output = Output()
        guard (try? process.run()) != nil else { return (-1, Data()) }
        DispatchQueue.global().async {
            output.data = pipe.fileHandleForReading.readDataToEndOfFile()
            output.done.signal()
        }
        guard output.done.wait(timeout: .now() + timeout) == .success else {
            kill(process.processIdentifier, SIGKILL)
            return (-1, Data())
        }
        process.waitUntilExit()
        return (process.terminationStatus, output.data)
    }

    private final class Output: @unchecked Sendable {
        let done = DispatchSemaphore(value: 0)
        var data = Data()
    }

    static var lastError: String { String(cString: strerror(errno)) }

    /// Whether this process has Full Disk Access, which removing a local
    /// account takes (step 6's drill): macOS's own privacy database opens
    /// only with it, even for root.
    static var fullDiskAccess: Bool {
        let fd = open("/Library/Application Support/com.apple.TCC/TCC.db", O_RDONLY)
        guard fd >= 0 else { return false }
        close(fd)
        return true
    }
}

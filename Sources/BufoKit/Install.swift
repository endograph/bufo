import Foundation

/// The names one install chose (PLAN.md, Product shape), kept beside the
/// installed binary as `<binary>.json`, root's alone, so the CLI finds its
/// daemon and uninstall finds what install made, with no fixed path in the
/// code. Names only, never a placement.
public struct InstallConfig: Codable, Sendable, Equatable {
    /// The launchd label, which is also the log subsystem.
    public var label: String
    /// The Mach service the CLI and hosts connect to.
    public var service: String
    /// The root-only state directory.
    public var state: String
    /// The binary's directory, when install made it.
    public var madeDirectory: String?

    public init(label: String, service: String, state: String, madeDirectory: String? = nil) {
        self.label = label
        self.service = service
        self.state = state
        self.madeDirectory = madeDirectory
    }

    /// The job's plist, where launchd reads system daemons.
    public var plist: String { "/Library/LaunchDaemons/\(label).plist" }

    /// Where the config for the binary at `executable` lives.
    public static func url(beside executable: URL) -> URL {
        let resolved = executable.resolvingSymlinksInPath()
        return resolved.deletingLastPathComponent().appendingPathComponent(resolved.lastPathComponent + ".json")
    }

    public enum Found: Equatable, Sendable {
        case notInstalled
        case installed(InstallConfig)
        /// Present but not trustworthy or not readable.
        case refused(String)
    }

    /// The config beside `executable`, trusted only when it is a regular
    /// file with one link that root alone can write, checked on the
    /// descriptor actually read, in a directory root alone can change. The names
    /// lead the CLI to a service whose code signature it still checks; this
    /// keeps it from following names someone else planted.
    public static func find(beside executable: URL) -> Found {
        let url = url(beside: executable)
        let fd = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
        guard fd >= 0 else {
            return errno == ENOENT ? .notInstalled : .refused("\(url.path): \(String(cString: strerror(errno)))")
        }
        let file = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
        var info = stat()
        guard fstat(fd, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_nlink == 1, rootsAlone(info),
              !grantsMore(acl_get_fd_np(fd, ACL_TYPE_EXTENDED)),
              (try? rootsAloneDirectory(url.deletingLastPathComponent().path)) != nil else {
            return .refused("\(url.path) isn't root's alone")
        }
        guard let data = try? file.read(upToCount: 64 * 1024),
              let config = try? JSONDecoder().decode(InstallConfig.self, from: data) else {
            return .refused("\(url.path) isn't a config")
        }
        return .installed(config)
    }
}

func rootsAlone(_ info: stat) -> Bool {
    info.st_uid == 0 && info.st_mode & (S_IWGRP | S_IWOTH) == 0
}

/// Whether a file's access list could grant more than its mode bits. Any
/// entry counts: the directories Bufo uses carry none, and a file made in a
/// directory without one inherits none.
func grantsMore(_ acl: acl_t?) -> Bool {
    guard let acl else { return errno != ENOENT }
    defer { acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    return acl_get_entry(acl, ACL_FIRST_ENTRY.rawValue, &entry) == 0
}

/// The directory at `path`, its symlinks resolved, refused unless it and
/// every directory above it belong to root, no one else can write them, and
/// they carry no access list.
/// Below such a directory only root can swap a file between a check and its
/// use, so plain paths are safe there.
public func rootsAloneDirectory(_ path: String) throws -> String {
    guard let resolved = realpath(path, nil) else {
        throw Refusal("\(path): \(String(cString: strerror(errno)))")
    }
    defer { free(resolved) }
    let real = String(cString: resolved)
    var walked = ""
    for component in [""] + real.split(separator: "/").map(String.init) {
        walked += component.isEmpty ? "/" : (walked == "/" ? "" : "/") + component
        var info = stat()
        guard lstat(walked, &info) == 0, info.st_mode & S_IFMT == S_IFDIR, rootsAlone(info),
              !grantsMore(acl_get_link_np(walked, ACL_TYPE_EXTENDED)) else {
            throw Refusal("\(walked) isn't a directory root alone can change")
        }
    }
    return real
}

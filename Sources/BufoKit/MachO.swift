import Foundation

/// The UUIDs (`LC_UUID`) of every slice of a Mach-O file, as the unified log
/// reports a process's `processImageUUID`; empty for anything else.
enum MachO {
    static func uuids(of path: String) -> Set<String> {
        guard let data = System.read(path, limit: 64 * 1024 * 1024) else { return [] }
        switch data.word(0, bigEndian: true) {
        case 0xCAFE_BABE, 0xCAFE_BABF: // fat, 32- or 64-bit offsets
            let wide = data.word(0, bigEndian: true) == 0xCAFE_BABF
            let count = min(Int(data.word(4, bigEndian: true) ?? 0), 16)
            let stride = wide ? 32 : 20
            return (0..<count).reduce(into: []) { found, index in
                let entry = 8 + index * stride
                let offset = wide ? data.doubleWord(entry + 8, bigEndian: true).map(Int.init)
                    : data.word(entry + 8, bigEndian: true).map(Int.init)
                if let offset, let uuid = sliceUUID(data, at: offset) { found.insert(uuid) }
            }
        default:
            return sliceUUID(data, at: 0).map { [$0] } ?? []
        }
    }

    /// A 64-bit little-endian slice's `LC_UUID`.
    private static func sliceUUID(_ data: Data, at slice: Int) -> String? {
        guard data.word(slice, bigEndian: false) == 0xFEED_FACF, let count = data.word(slice + 16, bigEndian: false) else {
            return nil
        }
        var command = slice + 32
        for _ in 0..<min(Int(count), 4096) {
            guard let kind = data.word(command, bigEndian: false), let size = data.word(command + 4, bigEndian: false),
                  size >= 8 else { return nil }
            if kind == 0x1B, size >= 24, command + 24 <= data.count { // LC_UUID
                let bytes = data[data.startIndex + command + 8 ..< data.startIndex + command + 24]
                return UUID(uuid: Array(bytes).withUnsafeBytes { $0.load(as: uuid_t.self) }).uuidString
            }
            command += Int(size)
        }
        return nil
    }
}

private extension Data {
    func word(_ offset: Int, bigEndian: Bool) -> UInt32? {
        guard offset >= 0, offset + 4 <= count else { return nil }
        let bytes = self[startIndex + offset ..< startIndex + offset + 4]
        return bytes.reduce(UInt32(0)) { bigEndian ? $0 << 8 | UInt32($1) : $0 >> 8 | UInt32($1) << 24 }
    }

    func doubleWord(_ offset: Int, bigEndian: Bool) -> UInt64? {
        guard let high = word(offset, bigEndian: bigEndian), let low = word(offset + 4, bigEndian: bigEndian) else { return nil }
        return bigEndian ? UInt64(high) << 32 | UInt64(low) : UInt64(low) << 32 | UInt64(high)
    }
}

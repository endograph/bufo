import Foundation

/// An `ssh_config` as text, read only as far as imitating it needs: each
/// line's keyword and value with the exact text before the value, and where
/// each `Host` or `Match` block's options start and end. Writing it back
/// changes nothing but what is inserted or removed.
struct SSHConfigText {
    struct Line {
        var text: String
        /// Lowercased; nil for a blank line or a comment.
        var keyword: String?
        var value: String
        /// Indentation, the keyword as written, and the separator.
        var prefix: String
    }

    struct Block {
        /// From the `Host` or `Match` line to its last option line.
        var lines: Range<Int>
        var host: Bool
        var patterns: [String]
    }

    var lines: [Line]
    var blocks: [Block] = []

    init(_ text: String) {
        lines = text.split(separator: "\n", omittingEmptySubsequences: false).map { Self.line(String($0)) }
        var start: Int?
        var last = 0
        func close() {
            guard let start else { return }
            let line = lines[start]
            blocks.append(Block(lines: start..<last + 1, host: line.keyword == "host",
                                patterns: line.value.split(whereSeparator: \.isWhitespace).map(String.init)))
        }
        for (index, line) in lines.enumerated() where line.keyword != nil {
            if line.keyword == "host" || line.keyword == "match" {
                close()
                start = index
            }
            last = index
        }
        close()
    }

    static func line(_ text: String) -> Line {
        let body = text.drop { $0 == " " || $0 == "\t" }
        guard let first = body.first, first != "#" else { return Line(text: text, keyword: nil, value: "", prefix: text) }
        let keyword = body.prefix { $0 != " " && $0 != "\t" && $0 != "=" }
        var rest = body.dropFirst(keyword.count)
        let separator = rest.prefix { $0 == " " || $0 == "\t" || $0 == "=" }
        rest = rest.dropFirst(separator.count)
        let value = String(rest).trimmingCharacters(in: .whitespaces)
        return Line(text: text, keyword: keyword.lowercased(), value: value,
                    prefix: String(text.prefix(text.count - rest.count)))
    }

    /// The text, unchanged.
    var text: String { lines.map(\.text).joined(separator: "\n") }

    /// The options of `block`, in order, comments and blanks left out.
    func options(_ block: Block) -> [Line] { lines[block.lines].filter { $0.keyword != nil } }

    /// What to insert after `block` for `entry`'s lines: as many blank lines
    /// as follow it (or precede it, when it's last), then the entry. The
    /// result is found and removed whole later (`removing`).
    func insertion(after block: Block, entry: [String]) -> String {
        func blanks(_ indices: some Sequence<Int>) -> (count: Int, reachedEnd: Bool) {
            var count = 0
            for index in indices {
                guard lines[index].text.trimmingCharacters(in: .whitespaces).isEmpty else { return (count, false) }
                count += 1
            }
            return (count, true)
        }
        var gap = blanks(block.lines.upperBound..<lines.count)
        if gap.reachedEnd { gap = blanks(stride(from: block.lines.lowerBound - 1, through: 0, by: -1)) }
        return "\n" + (Array(repeating: "", count: gap.count) + entry).joined(separator: "\n")
    }

    /// `text` with `insertion` placed after `block`'s last option line.
    func inserting(_ insertion: String, after block: Block) -> String {
        let before = lines[..<block.lines.upperBound].map(\.text).joined(separator: "\n")
        let after = lines[block.lines.upperBound...].map(\.text).joined(separator: "\n")
        return before + insertion + (block.lines.upperBound < lines.count ? "\n" + after : "")
    }

    /// `text` without `insertion`, if it holds it exactly once; the same
    /// text if it holds none; nil if more.
    static func removing(_ insertion: String, from text: String) -> String? {
        let parts = text.components(separatedBy: insertion)
        guard parts.count <= 2 else { return nil }
        return parts.joined()
    }
}

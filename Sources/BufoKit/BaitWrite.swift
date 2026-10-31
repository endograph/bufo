import Foundation

/// The script that makes `BaitChange`s in the bait laptop's `~/.ssh`, run
/// there as its owner (PLAN.md, Placing bait, step 2): every check before
/// any change, then each file written to a temporary name and renamed (or
/// linked, where nothing may be replaced), its mode and time set; links
/// refused. The temporary name is the operation's own, `scratch`, so a run
/// that was killed leaves nothing the next one doesn't clear first. It
/// prints `ok`, or `fail` and a word that names no file, and nothing else.
enum BaitWrite {
    static func script(_ changes: [BaitChange], scratch: String) -> String {
        var checks: [String] = [], applies: [String] = []
        for change in changes {
            switch change {
            case .create(let name, let content, let mode, let modified):
                let n = shellQuote(name), sum = sha256(content)
                checks.append("if [ -L \(n) ]; then fail link; elif [ -e \(n) ]; then [ \"$(sum \(n))\" = \(shellQuote(sum)) ] || fail exists; fi")
                applies.append("""
                    if [ ! -e \(n) ]; then
                      new
                      printf %s \(shellQuote(content.base64EncodedString())) | base64 -D > "$t" && chmod \(String(mode, radix: 8)) "$t" \
                    && touch -d \(timestamp(modified)) "$t" && ln "$t" \(n) || fail write
                      rm -f "$t"
                    fi
                    """)
            case .replace(let name, let expect, let content):
                let n = shellQuote(name), sum = sha256(content)
                checks.append("[ -f \(n) ] && [ ! -L \(n) ] || fail changed; c=$(sum \(n)); [ \"$c\" = \(shellQuote(expect)) ] || [ \"$c\" = \(shellQuote(sum)) ] || fail changed")
                applies.append("""
                    if [ "$(sum \(n))" != \(shellQuote(sum)) ]; then
                      new
                      printf %s \(shellQuote(content.base64EncodedString())) | base64 -D > "$t" && chmod "$(stat -f %Lp \(n))" "$t" \
                    && touch -r \(n) "$t" && mv -f "$t" \(n) || fail write
                    fi
                    """)
            case .append(let name, let expect, let line):
                let n = shellQuote(name), l = shellQuote(line)
                checks.append("[ -f \(n) ] && [ ! -L \(n) ] || fail changed; grep -qxF -- \(l) \(n) || [ \"$(sum \(n))\" = \(shellQuote(expect)) ] || fail changed")
                applies.append("""
                    if ! grep -qxF -- \(l) \(n); then
                      new
                      cat \(n) > "$t" || fail write
                      [ ! -s \(n) ] || [ "$(tail -c 1 \(n) | od -An -tx1 | tr -d ' ')" = 0a ] || printf '\\n' >> "$t"
                      printf '%s\\n' \(l) >> "$t" && chmod "$(stat -f %Lp \(n))" "$t" && touch -r \(n) "$t" && mv -f "$t" \(n) || fail write
                    fi
                    """)
            case .delete(let name, let expect):
                let n = shellQuote(name)
                checks.append("if [ -L \(n) ]; then fail link; elif [ -e \(n) ]; then [ \"$(sum \(n))\" = \(shellQuote(expect)) ] || fail changed; fi")
                applies.append("rm -f \(n) || fail write")
            case .dropLine(let name, let line):
                let n = shellQuote(name), l = shellQuote(line)
                checks.append("[ ! -L \(n) ] || fail link")
                applies.append("""
                    if [ -f \(n) ] && grep -qxF -- \(l) \(n); then
                      new
                      grep -vxF -- \(l) \(n) > "$t"; [ $? -le 1 ] || fail write
                      chmod "$(stat -f %Lp \(n))" "$t" && touch -r \(n) "$t" && mv -f "$t" \(n) || fail write
                    fi
                    """)
            }
        }
        return """
            export LC_ALL=C PATH=/usr/bin:/bin:/usr/sbin:/sbin
            umask 077
            exec 2>/dev/null
            fail() { echo "fail $1"; exit 0; }
            sum() { shasum -a 256 < "$1" | cut -c1-64; }
            S=$HOME/.ssh
            [ -d "$S" ] && [ ! -L "$S" ] && cd "$S" || fail missing
            t=./\(shellQuote("." + scratch))
            rm -f "$t"
            trap 'rm -f "$t"' EXIT
            new() { rm -f "$t" && (set -C; : > "$t") || fail write; }
            \(checks.joined(separator: "\n"))
            \(applies.joined(separator: "\n"))
            echo ok

            """
    }

    /// Why a run failed, in words that name no file; nil when it didn't.
    static func failure(_ output: Data, status: Int32) -> String? {
        let last = String(decoding: output, as: UTF8.self).split(separator: "\n").last.map(String.init) ?? ""
        if status == 0, last == "ok" { return nil }
        switch last {
        case "fail changed": return "a file on the bait laptop changed since the survey"
        case "fail exists": return "a file on the bait laptop is already where the bait would go"
        case "fail link": return "a file on the bait laptop is a link, which planting doesn't follow"
        case "fail missing": return "the bait laptop has no ~/.ssh directory"
        case "fail write": return "a file on the bait laptop couldn't be written"
        default: return "the bait laptop's script didn't finish (exit \(status))"
        }
    }

    /// `touch -d`'s form, in UTC.
    static func timestamp(_ seconds: Int) -> String {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime]
        return formatter.string(from: Date(timeIntervalSince1970: TimeInterval(seconds)))
    }
}

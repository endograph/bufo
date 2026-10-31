import Foundation

/// What a bait laptop's `~/.ssh` shows (PLAN.md, Placing bait on the bait
/// laptop), read by a script run there as its owner over SSH: a bounded
/// listing, the private keys' public halves and whether they have
/// passphrases, `.pub` lines, the config, what `ssh -G` resolves for every
/// concrete `Host` name and one name that matches none, what each agent
/// holds, and which hosts `known_hosts` knows. Untrusted, and kept only
/// while a placement is made or checked.
struct BaitSurvey: Equatable {
    struct File: Equatable {
        var regular: Bool
        var mode: Int
        var size: Int
        var modified: Int
        /// SHA-256 of a regular file up to a megabyte.
        var sum: String?
    }

    struct Key: Equatable {
        var name: String
        var passphrase: Bool
        /// The first line, which says the format.
        var header: String
        /// From `ssh-keygen -y` when it has no passphrase.
        var publicLine: String?
    }

    var user = ""
    var home = ""
    var files: [String: File] = [:]
    var keys: [Key] = []
    /// Each `.pub` file's first line.
    var pubs: [String: String] = [:]
    var config: String?
    /// `ssh -G` for each name: keyword to values, in order.
    var resolved: [String: [String: [String]]] = [:]
    var agent: [String] = []
    /// Local accounts with ids from 501.
    var accounts: [String] = []
    var knownLines = 0
    var knownHashed = 0
    /// Names `known_hosts` has a key for, as ssh looks them up.
    var known: Set<String> = []
    /// Every `IdentityFile` value in the config and its includes, whatever
    /// block it's in, as written.
    var identities: [String] = []

    /// OpenSSH's default identity names, which ssh offers with no config.
    static let defaultNames: Set<String> = ["id_rsa", "id_ecdsa", "id_ecdsa_sk", "id_ed25519", "id_ed25519_sk", "id_dsa", "id_xmss"]

    /// The script, POSIX sh with the system's tools. `lookups` are names
    /// to check in `known_hosts`; `probe` matches no `Host` line, so it
    /// shows what `Host *` and `Match all` give anything. `configOption` is
    /// for tests, which can't move ssh's idea of home.
    static func script(lookups: [String], probe: String, configOption: String = "") -> String {
        let quoted = lookups.map(shellQuote).joined(separator: " ")
        return #"""
        export LC_ALL=C PATH=/usr/bin:/bin:/usr/sbin:/sbin
        umask 077
        exec 2>/dev/null
        b() { printf %s "$1" | base64 | tr -d '\n'; }
        r() { printf %s "$1"; shift; for _r in "$@"; do printf ' %s' "$(b "$_r")"; done; printf '\n'; }
        S=$HOME/.ssh
        if [ -L "$S" ] || [ ! -d "$S" ]; then r refuse "~/.ssh isn't a directory"; r end; exit 0; fi
        cd "$S" || exit 1
        r me "$(id -un)" "$HOME"
        n=0
        for f in * .[!.]* ..?*; do
          [ -e "$f" ] || [ -L "$f" ] || continue
          n=$((n + 1)); [ "$n" -le 256 ] || { r refuse "~/.ssh holds too many files"; r end; exit 0; }
          s=; t=other
          if [ -L "$f" ]; then t=link; elif [ -f "$f" ]; then t=file; fi
          if [ "$t" = file ] && [ "$(stat -f %z "$f")" -le 1048576 ]; then s=$(shasum -a 256 < "$f" | cut -c1-64); fi
          r file "$f" "$t" "$(stat -f '%Lp %z %m' "$f")" "$s"
          if [ "$t" = file ] && [ "$(stat -f %z "$f")" -le 65536 ]; then
            h=$(head -n 1 "$f" 2>/dev/null | head -c 64)
            case "$h" in
              -----BEGIN*PRIVATE\ KEY-----*)
                if p=$(ssh-keygen -y -P '' -f "$f" 2>/dev/null); then r key "$f" no "$h" "$p"; else r key "$f" yes "$h" ""; fi ;;
            esac
            case "$f" in *.pub) r pub "$f" "$(head -n 1 "$f" | head -c 16384)" ;; esac
          fi
        done
        if [ -f config ] && [ ! -L config ] && [ "$(stat -f %z config)" -le 65536 ]; then
          printf 'config %s\n' "$(base64 < config | tr -d '\n')"
        fi
        # A keyword's values as ssh reads them: any case, then spaces or one =, trimmed.
        values() {
          awk -v k="$1" '{ l = $0; sub(/^[ \t]+/, "", l); w = l; sub(/[ \t=].*$/, "", w) }
            tolower(w) == k { sub(/^[^ \t=]+[ \t]*=?[ \t]*/, "", l); sub(/[ \t\r]+$/, "", l); print l }' "$2"
        }
        hosts() { values host "$1" | tr ' \t' '\n\n'; }
        identities() { values identityfile "$1"; }
        names=$(hosts config)
        ids=$(identities config)
        top=$(values include config)
        case "$top" in *\"*) r refuse "an ssh config includes a quoted path, which planting doesn't read"; r end; exit 0 ;; esac
        for p in $top; do
          case "$p" in "~/"*) p=$HOME/${p#"~/"} ;; /*) ;; *) p=$S/$p ;; esac
          for g in $p; do
            [ -f "$g" ] || continue
            [ -z "$(values include "$g")" ] || { r refuse "an included ssh config includes another, which planting doesn't read"; r end; exit 0; }
            names="$names
        $(hosts "$g")"
            ids="$ids
        $(identities "$g")"
          done
        done
        printf '%s\n' "$ids" | while IFS= read -r i; do [ -n "$i" ] && r identity "$i"; done
        concrete=$(printf '%s\n' "$names" | grep -v '[*?!]' | grep -v '^$' | sort -u)
        [ "$(printf '%s\n' "$concrete" | grep -c .)" -le 64 ] || { r refuse "the ssh config names more hosts than planting reads"; r end; exit 0; }
        known() {
          [ -f known_hosts ] && ssh-keygen -F "$1" -f known_hosts >/dev/null && r known "$1"
        }
        for n in $concrete \#(shellQuote(probe)); do
          g=$(ssh \#(configOption) -G "$n" | grep -E '^(hostname|user|port|identityfile|hostkeyalias|identitiesonly|addkeystoagent) ' | head -n 64)
          r resolved "$n" "$g"
          k=$(printf '%s\n' "$g" | awk '$1 == "hostkeyalias" { a = $2 } $1 == "hostname" { h = $2 } $1 == "port" { p = $2 }
            END { n = (a != "" ? a : h); if (p != "" && p != "22") n = "[" n "]:" p; print n }')
          [ -n "$k" ] && known "$k"
        done
        for k in \#(quoted); do known "$k"; done
        if [ -f known_hosts ]; then r knownhosts "$(grep -c '' known_hosts)" "$(grep -c '^|1|' known_hosts)"; fi
        for s in "${SSH_AUTH_SOCK:-}" "$(launchctl getenv SSH_AUTH_SOCK 2>/dev/null)" agent/*; do
          [ -S "$s" ] || continue
          r agent "$(SSH_AUTH_SOCK=$s ssh-add -L 2>/dev/null | head -n 64)"
        done
        r accounts "$(dscl . -list /Users UniqueID 2>/dev/null | awk '$2 >= 501 { print $1 }' | head -n 64)"
        r end

        """#
    }

    /// Reads the script's output; refuses anything cut short or malformed.
    init(output: Data) throws {
        guard output.count <= 4 * 1024 * 1024, let text = String(data: output, encoding: .utf8) else {
            throw Refusal("the bait laptop's survey didn't read")
        }
        var ended = false
        for line in text.split(separator: "\n", omittingEmptySubsequences: true) {
            let words = line.split(separator: " ", omittingEmptySubsequences: false)
            let fields = try words.dropFirst().map { word -> String in
                guard let data = Data(base64Encoded: String(word)), let field = String(data: data, encoding: .utf8) else {
                    throw Refusal("the bait laptop's survey didn't read")
                }
                return field
            }
            func field(_ index: Int) -> String { index < fields.count ? fields[index] : "" }
            switch words.first {
            case "refuse": throw Refusal("on the bait laptop, \(field(0))")
            case "me":
                user = field(0)
                home = field(1)
            case "file":
                let numbers = field(2).split(separator: " ").compactMap { Int($0) }
                guard numbers.count == 3, let mode = Int(String(numbers[0]), radix: 8),
                      field(3).isEmpty || field(3).wholeMatch(of: /[0-9a-f]{64}/) != nil else {
                    throw Refusal("the bait laptop's survey didn't read")
                }
                files[field(0)] = File(regular: field(1) == "file", mode: mode, size: numbers[1], modified: numbers[2],
                                       sum: field(3).isEmpty ? nil : field(3))
            case "key":
                keys.append(Key(name: field(0), passphrase: field(1) == "yes", header: field(2),
                                publicLine: field(3).isEmpty ? nil : field(3)))
            case "pub": pubs[field(0)] = field(1)
            case "config": config = field(0)
            case "resolved":
                var options: [String: [String]] = [:]
                for option in field(1).split(separator: "\n") {
                    let parts = option.split(separator: " ", maxSplits: 1)
                    guard parts.count == 2 else { continue }
                    options[String(parts[0]), default: []].append(String(parts[1]))
                }
                resolved[field(0)] = options
            case "known": known.insert(field(0))
            case "identity": identities.append(field(0))
            case "knownhosts":
                knownLines = Int(field(0)) ?? 0
                knownHashed = Int(field(1)) ?? 0
            case "agent": agent += field(0).split(separator: "\n").map(String.init)
            case "accounts": accounts = field(0).split(separator: "\n").map(String.init)
            case "end": ended = true
            default: break
            }
        }
        guard ended, !home.isEmpty else { throw Refusal("the bait laptop's survey was cut short") }
    }

    init() {}
}

/// `text` as one word for sh.
func shellQuote(_ text: String) -> String {
    "'" + text.replacingOccurrences(of: "'", with: #"'\''"#) + "'"
}

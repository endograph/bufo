# Bufo implementation plan

Drafted 2026-10-29 by Claude for the owner, from `ARCHITECTURE.md` and
Froggy's prior art; reviewed adversarially by Codex Astra, then the whole
repository by Codex Sol, and revised. Milestone 1's first two steps are
done. A **proposal** waits on the owner; **decided** names who decided.

Milestone 1 must work where a watcher can be dialed but dials no one, so
the watcher that plants bait may not be the one that detects it. Below,
the **first watcher** detects and dials no one; the **second watcher**
dials it and the **bait laptop**, and plants.

## What was checked

Read-only checks on Apple-silicon Macs running macOS 27.0.1, the macOS 27
SDK, and Apple's and OpenSSH's published sources, 2026-10-29:

- sshd is OpenSSH 10.3p1, started per connection by launchd (inetd-style,
  `com.openssh.sshd`), so a config change applies to the next connection
  with nothing to reload. `/etc/ssh/sshd_config` begins with `Include
  /etc/ssh/sshd_config.d/*`; the directory holds Apple's `100-macos.conf`.
- At sshd's default `LogLevel INFO`, `Accepted publickey for <user> from
  <address> port <n> ssh2: <type> SHA256:<fingerprint>` reaches the unified
  log from `sshd-session` at Info level, not redacted. Info is held in memory for
  minutes unless a logging preference persists it (E3, E3b), which a
  LaunchDaemon can't write (step 4). An admin
  account reads these lines without sudo.
- `openssh_login` (Endpoint Security) carries success, a result type, the
  source address, the username, and the uid: **no key fingerprint**. It
  can identify the decoy only by its account.
- Remote Login limited to some users is enforced by `pam_sacl` in PAM's
  account phase, after the key is checked. Apple's published `auth2.c`
  logs the authentication before the PAM account check, so a key may log
  `Accepted` and still be refused a login (E5).
- Apple excludes launch daemons from the data protection keychain (TN3137).
- `/Applications` is `root:admin 775` and bundles copied there belong to
  the owner, so the owner's account (and anything running as it) can
  replace any app there. Froggy's spike found App Management protected no
  Apple Development signed app.
- Standalone Tailscale (`io.tailscale.ipn.macsys`) keeps its LocalAPI port
  as a root-owned symlink in `/Library/Tailscale`; `tailscale whois` works
  from the owner's shell.
- A node shared into a tailnet one way is dialed and dials no one; replies
  on an incoming connection are allowed.
- With FileVault on, nothing of a watcher runs after a restart until
  someone unlocks it; with FileVault and automatic login off, daemons run
  but no login session (and no host app) does until someone logs in.
- Froggy's mesh is TLS 1.2 with pre-shared keys (Network.framework) plus an
  HMAC over the session's exporter secret: no bearer token is presented
  that a host could hash.

## 1. Product shape and packaging

**Swift.** CryptoKit's Secure Enclave keys, the Security framework's
code-signing requirements, XPC, `os` logging, Network.framework's TLS, and
Endpoint Security later (a C API, called from Swift) are all first class
there; the phone already speaks CryptoKit P-256; and Froggy, the first
host, is Swift, so the contract is a package it links with no bridge. No
third-party dependencies.

**One Swift package at the repository root** (proposal):

- `BufoContract`: library, no dependencies, macOS and iOS. What a host and
  the phone need: the XPC request and response types, incidents, health
  beacons, and status (types with no placement field), the signed formats,
  and their verification. Froggy links only this.
- `BufoKit`: library, the watcher: store, decoy kinds, detectors,
  incidents, peers, the host listener. Never linked by a host.
- `bufo`: one executable, both the JSON CLI and the daemon (`bufo daemon`,
  only as launchd starts it, as root). One signed binary keeps the
  artifacts and the requirement to one identifier.
- Later, the collector: an app bundle carrying an Endpoint Security system
  extension, the only part that needs a bundle (its entitlement comes in a
  provisioning profile).

**Identifiers.** The signing identifier and the reverse-DNS prefix are
build settings, from the builder's private config (`.bufo/`, ignored), with
a generic public default. The process name, launchd label, Mach service
name, state paths, port, and log subsystem are chosen at install, from
options the owner gives; none are literals in the code. The code signature
still names the team and identifier, which a careful intruder can read
from any process; that is the visibility the design accepts.

**How the privileged part runs** (proposal: a classic LaunchDaemon, not
`SMAppService`):

- `SMAppService.daemon` reads its plist from inside the signed bundle, so
  the label, Mach service, and program are fixed at signing and per-install
  names are impossible. Its bundle should sit in `/Applications`, which the
  owner's account can write; the SDK requires a notarized app and may need
  re-registration when the job changes. A root daemon whose executable the
  owner's account can replace is owner-to-root escalation, unless launchd
  refuses the replacement (E6).
- Instead, `sudo bufo install` puts the binary in a root-owned directory
  (`root:wheel`, `0755`, no parent writable by the owner), under the
  chosen name, writes a root-owned plist to `/Library/LaunchDaemons` under
  the chosen label, with the chosen `MachServices` name and a
  `SpawnConstraint` requiring the team and identifier (documented for
  third-party plists; E6 checks it's enforced), and bootstraps it. macOS
  shows it in Login Items & Extensions under the signing team and posts a
  background-item notification; it is never hidden.
- State lives in a root-only directory (`0700`), excluded from Time Machine.

**Root file handling** (install, update, plant, uninstall): every write
goes into a directory root alone can change: it and every directory above
it belong to root, no one else can write them, and none carries an access
list. Below such a directory only root can swap a file between a check
and its use, so plain paths are safe there. New files are opened with
`O_EXCL` and `O_NOFOLLOW`; replacements are written beside and renamed.
An artifact is copied first to a fresh hidden name beside its
destination, and that copy is the one checked and installed. The pin is
the running build's own team and identifier, read from the code that is
running, so swapping the file it was launched from changes nothing. The
check: that requirement, the hardened runtime flag, no entitlements, and a
version (a signed integer in its Info.plist; at install the running
build's own, at update strictly greater than the installed one; the
six-character stamp is only for people).

**Bootstrap.** The first install runs a binary the owner fetched; the owner
checks it before `sudo` with `codesign --verify --strict` and `codesign
-dv` (team and identifier) and, with Developer ID, `spctl --assess`. The
README will say so; nothing on the machine can check it for them.

**The JSON CLI.** Every command prints one JSON object on stdout and exits
nonzero on failure, with `{"error": …}`; output types come from
`BufoContract`, which has no placement fields. Not run as root, the CLI
reads only `status`: installed, role, kinds on, detector coverage, peers'
health, delivery health, open incidents by kind. As root: `install`,
`uninstall`, `plant`, `rotate`, `update`, `arm`, `retire`, `peer add|remove`, `host
add|remove`, `close`. Every change takes root at the watcher, and no
command shows a placement (decided 2026-10-29, the owner).

**Install** (`sudo bufo install --binary … --state … --label … --service
…`, built in step 3): the binary's directory (made if missing, under
directories root alone can change), the artifact copied in and then
checked, the config beside it, the state directory with the watcher's id,
the plist, then bootstrap and wait for `status` to answer with the
installed version. `update` runs from the installed binary and keeps the
old one until the new one answers. Peers and hosts are pinned afterwards,
each by its own command: `peer add` (a secret made on one side and entered
on the other once, the other's tailnet address, and whether it may plant
here, 5) and `host add` (one code-signing requirement and one local user
per host app).

If any step fails, install removes what it made. Uninstall removes the
job, binary, state, decoy accounts, and Bufo's sshd file, the binary and
its config last so that a failed uninstall can run again, and leaves the
owner's own SSH configuration alone. Bait on a machine that is offline
stays there, and `uninstall` says which machines still hold it; system
records (logs, Login Items history) are outside its reach and it says
nothing about them.

**Build and deploy** (proposal; the owner decides):

- `make build` runs `scripts/build.sh`: `swift build -c release`, then
  `codesign` with the hardened runtime, a secure timestamp, no
  `get-task-allow`; Apple Development until Developer ID exists, then
  `notarytool` on a zip.
- Signing happens off the machines where agents run, or with the
  identity's key in hardware: anything that can sign as the team can
  become Bufo.
- Deploy is not an agent's job (Agents get nothing): an agent that can
  install Bufo can replace a root daemon. A deployer may carry a signed
  artifact to a watcher; installing or updating takes the owner, as root
  at that watcher.

## 2. The watcher process model

**One process: the root daemon.** It reads the unified log, runs
detectors, keeps incidents, talks to peers and hosts. Hosts and the CLI
reach it through its Mach service.

**The store's key** (decided 2026-10-29, the owner): a CryptoKit
`SecureEnclave.P256` key with no user presence, its `dataRepresentation` a
root-only file beside the store. A root daemon can use one; the data
protection keychain refuses it (E1). The sealed key is useless off this
Secure Enclave; any root process on the watcher can use it while there,
which is where the design already draws its line. Rejected: a per-user key
holder in the data protection keychain (a provisioning profile, a login
session, and a second process in the owner's account, where agents run),
and a file-based System keychain item (legacy, prompt-based ACLs that root
can rewrite). Milestone 1 keeps root-only files without it and says so in
`status`; the key comes after v1 signing (M4).

**What root-only state doesn't hide.** On the detecting watcher, the decoy
account exists in Directory Services and its name appears in sshd's log
lines, both readable by the owner's admin account. An intruder holding the
owner's account on the detecting watcher can find the decoy account and
match it to the bait laptop's `User` lines without using it. The secrecy of
the SSH decoy holds against an intruder who holds the bait laptop alone,
and only while the bait laptop's real credentials don't open the owner's
account on the detecting watcher (Concerns).

## 3. The SSH-key decoy, end to end

**On the detecting watcher** (as root, armed by a planting peer root there
allowed to plant, 5, or by root there with `bufo arm <account> <public
key file>`; `bufo retire <account>` undoes it; at most 4 at once):

- **An account.** A new local account, standard (not admin), hidden, no
  password (`*`), shell `/usr/bin/false`, the first free id from 501, a
  home directory in `/Users` owned by root and not group- or
  world-writable, holding `.ssh/authorized_keys` owned by
  the account, `0600`. Its name comes from the planting watcher's survey of
  the bait laptop (4). It stays out of `com.apple.access_ssh` and out of
  Sharing's list. PAM's account check refuses it twice over (the access
  group, and OpenDirectory's shell check, which rejects `/usr/bin/false`),
  after sshd has checked the key and logged its fingerprint, so a client
  holding the decoy trips and never gets a session (E5).
- **The key line.** `restrict,command="/usr/bin/false" <public key>`, a
  backstop should PAM ever admit the account: `restrict` turns off port,
  agent, X11, and Unix-socket forwarding, the pty, and `~/.ssh/rc`, and
  `PermitTunnel no` (the macOS default) is checked in sshd's effective
  config (`sshd -T`) at plant and at each health check.
- **sshd.** One file in `/etc/ssh/sshd_config.d/`, named and ordered like
  its neighbours, containing only `LogLevel VERBOSE`, so keys offered and
  refused also log their fingerprints. No `Match` block naming the
  account, since `sshd_config.d` is world-readable. sshd takes the first
  value it reads, so the file sorts before any that sets `LogLevel`.

**Detection** (proposal: the unified log, streamed):

- The daemon runs Apple's `/usr/bin/log stream --style ndjson --level
  info --predicate 'processImagePath == "/usr/libexec/sshd-session"'` and
  keeps a line only if its `processImageUUID` matches the binary on disk
  and its `userID` is root or the decoy account's. A program named
  `sshd-session` anywhere else logs identical text but carries its own
  path, UUID, and user (E3).
- **Parsing.** Only enumerated message forms count, each matched whole,
  fields read from the right, lines bounded in size. For a decoy key, in
  order (E5): `Accepted key <type> SHA256:<fp> found at <file>:<line>` (sshd
  reading the decoy's `authorized_keys`, logged as the decoy's uid),
  `Postponed publickey for <account> from <address> port <n>`, then, as PAM
  refuses it, `Failed publickey for <account> from <address> port <n> ssh2:
  <type> SHA256:<fp>` and `fatal: Access denied for user <account> by PAM
  account configuration`. A fingerprint or account name anywhere else in a
  line is not a trip.
- **A trip** is the decoy's fingerprint in any of those lines, or the decoy
  account in any of them, from any source address, local ones included.
  The source and port come from the same connection's lines (one
  `sshd-session` process id).
- **Coverage.** sshd's lines are Info level, which macOS keeps in memory
  only: on a test watcher they were evicted after about 9 minutes, while
  default-level lines stayed for hours (E3). At start, and whenever the
  stream ends, the daemon starts a new stream and buffers it first, then
  reads history with `log show --info --start` from a connection
  window (10 minutes) before its last-seen line. Lines up to the last-seen
  one only rebuild which connections were already counted, so none counts
  twice; a connection is its `sshd-session` process id from its
  `Connection from` line, so a reused id is a new one. A stream that ends, a
  gap history can't cover, or a restart with no history back to the
  last-seen line is **degraded coverage** (a line is matched across the
  two by its boot, process, message, and a Mach time within 100 µs: the
  stream names no boot, its timestamps run milliseconds after history's,
  and its Mach times a few ticks off): a health fact peers see and
  alarm on, never silent. It lasts until the next self-test passes, which
  runs a minute after the stream restarts; a restart whose history reaches
  the last-seen line left no gap, and reading it back isn't degraded (step
  5's drill caught a restart alarming its peer for the second it took). Since sshd's Info lines last minutes in
  memory, a restart after a quiet spell usually can't find its last-seen
  line and reports a degraded minute until the self-test; a longer outage
  is a silence peers alarm on (7). A per-process logging preference
  persisting Info would read the gap back (E3b), but macOS keeps it in
  `/Library/Preferences/Logging/Processes`, which the daemon can't write
  (EPERM in step 4's drill, where a root shell over SSH could), and `log
  config --process` sets modes only on running processes; Bufo sets none.
- **Self-test.** Every few hours the daemon offers a fresh, unauthorized
  key for one of macOS's own service accounts (a leading underscore, an id
  below 500, `/usr/bin/false`), chosen at random once per watcher, with no
  `authorized_keys` (sshd logs `Failed publickey for <account> … SHA256:<fp>`;
  for a name no account has it logs only `Invalid user`, with no
  fingerprint), and expects its fingerprint back within a minute. It proves sshd, logging, the stream, and the parser; only that
  exact fingerprint, recorded beforehand, is exempt, once. It never uses
  the decoy account, so it puts no line about it in the log. Separately,
  each health check confirms the decoy's account, key line, sshd file, and
  `PermitTunnel` are as planted; the full path (a trip reaching the phone)
  is a drill the owner runs.
- **`openssh_login`** joins with the collector (Order 5) as a second,
  independent source, by account and source address.

**On the bait laptop** (4): the private key, without a passphrase, under a
file name and comment in the style of its neighbours, and a `Host` entry in
`~/.ssh/config` pointing at the detecting watcher's tailnet name with the
decoy account as `User`, written in the style of the entries already there
(indentation, keyword order and case, `HostName` form, `HostKeyAlias`,
`IdentityFile`, `IdentitiesOnly`), placed among them. A `known_hosts` line
for the alias if the real entries have one (hashed if theirs are).
Modification times match the neighbours'; inode change times can't.

**Imitation without lists.** Every choice comes from the bait laptop's own
`~/.ssh` (surveyed over SSH, read-only, treated as untrusted data and kept
only while generating) and randomness: the key type the real keys use, a
file name, comment, alias, and account name formed as theirs are. Where
there's nothing to copy, the kind refuses rather than invent a shape. As
built (step 6):

- *The key* copies one real key without a passphrase and with a name that
  isn't a default: its type, size, and file format, its comment, its mode
  and its `.pub`'s, and a time among the real keys' (the `.pub` as far
  behind as its model's). Its name is the model's with each word that names
  a host or user the laptop reaches replaced by the decoy's; a name with no
  such word isn't a model.
- *The entry* copies a real concrete `Host` entry that names a `User` and
  uses only plain options (no proxy, forward, or command): its keywords in
  order, their case, indentation, and separators, inserted after it with
  the same blank lines around it. Where the template names its machine by
  address, dotted name, or bare name, the entry names the detector the
  same way (its tailnet address, or its name in DNS, which on a tailnet is
  its MagicDNS name). If the laptop already reaches the detector, the
  decoy is a second account there, named the detector's bare name and the
  account joined by the separator the laptop's names use most.
- *The account* is a user name the laptop already uses (in its config, in
  a key comment, or as a local account), never one it uses on the
  detector, its own, `root`, or a host's name.
- *`known_hosts`* gets a line for the detector, hashed if most are, only
  if the template's machine has one and the detector, by the name the
  entry looks it up under, hasn't.

**Comparisons it must survive** (ARCHITECTURE, Comparison). The survey
also records what an intruder could compare the decoy against, and the
kind refuses when it can't match:

- the real keys' passphrases and storage: a decoy has no passphrase, so a
  bait laptop whose real keys all have one, or live only in an agent or
  the Keychain, gets no SSH key decoy;
- whether the real keys' `.pub` files sit beside them, and their comments;
- whether the real keys are on a forge's public key list where the decoy
  can't be (the survey can't see that; the owner answers it at plant). Not
  asked yet (step 6): the decoy is named for a machine on the owner's
  network, which a forge wouldn't list; E10 tests whether that holds;
- `known_hosts` (above) and times (above);
- too few neighbours: one real key to copy from makes a near-copy, so the
  kind needs at least two;
- shell history naming the real aliases and never the decoy's. Bufo
  doesn't plant history (ARCHITECTURE, Rejected), so this one stays.

**Never offered by the owner's ssh.** A refused offer of the decoy's
fingerprint trips (Detection), so the owner's own client must never make
one. Planting refuses, and rotation re-checks, unless: the decoy's file is
none of OpenSSH's default identity names; `ssh -G` for every other `Host`
entry, and for a name that matches none, lists no `IdentityFile` that
resolves to it; and the bait laptop's agent (`ssh-add -L`) doesn't hold it.
`ssh -G` prints `IdentityFile` as written, tokens unexpanded, so a name
that matches none can't show a path built from the destination; planting
refuses any `IdentityFile` with a per-destination token (anything but
`%d`, `%u`, `%%`). With `AddKeysToAgent` on, someone who uses the decoy
there loads it into the owner's agent, which then offers it everywhere;
that follows a real trip and joins its incident.
The owner changes their config without Bufo, so a check at plant isn't
enough on its own; a scheduled read-only re-check comes with scheduled
rotation (Order 5).

**Network.** The kind declares the tailnet: the alias points at the
watcher's tailnet name and sshd answers there. A key taken and tried from
outside the tailnet never reaches the watcher and never trips; `status`
states that assumption, and canarytokens covers the rest (ARCHITECTURE,
Alongside canarytokens).

**Rotation** is a sequence of persisted states: new account and key armed
on the detector; bait written; bait verified (`ssh -G` on the bait laptop
resolves to it); old bait removed; old key retired. Detection is armed
before bait is exposed, and a crash resumes where it stopped. A spent key
stays authorized and watched until its incident closes, so an intruder who
keeps using it keeps adding to one incident. Milestone 1 rotates only when
the owner runs `bufo rotate`; rotation on a schedule and after every trip
is Order 5. Closing an incident doesn't mean its decoy rotated; `status`
shows spent decoys still planted.

## 4. Placing bait on the bait laptop

**A one-shot run there** (a Bufo binary run once) leaves Bufo's signed
binary and its first-run Gatekeeper and syspolicy records (team and
identifier, in root-only databases), a quarantine event if downloaded, and
shell history; and the laptop must get the placement from somewhere. The
records outlast the binary.

**A watcher over SSH** (built in step 6). The planting watcher need not be
the detecting one: a watcher that can't dial the bait laptop can't plant
there. The owner runs `sudo bufo plant ssh-key --bait <destination>
--detector <address>` on a watcher that can reach both. The daemon runs
the operation and keeps it; the CLI holds the owner's SSH access and only
carries scripts there and their output back. Each script runs with
`/usr/bin/ssh` as the owner (`SUDO_USER`), `-F /dev/null`, the bait
laptop's host key pinned in root-owned state (read with `ssh-keyscan` and
confirmed by the owner the first time), `/bin/sh -s` on the far side, and
the script on standard input, with the system's tools only.

1. **Survey**, read-only: a listing of `~/.ssh` (at most 256 entries:
   type, mode, size, time, SHA-256), each private key's first line and,
   via `ssh-keygen -y -P ''`, its public half or that it has a
   passphrase; `.pub` lines; the config; every `IdentityFile` line in the
   config and its includes, whatever block it's in; `ssh -G` for every
   concrete `Host` name there (refusing more than 64, or an include that
   includes another) and for one random name that matches none; which names `known_hosts` has (`ssh-keygen -F`) and how
   many lines are hashed; every agent's keys (`$SSH_AUTH_SOCK`, launchd's,
   and sockets in `~/.ssh/agent`); and local accounts from id 501. The
   output is base64 fields, bounded, and refused if cut short.
2. **Plan** (3, Imitation without lists), then **arm**: the detector arms
   the account and key (3), over the planting grant or here.
3. **Write**: every check first (a file changed since the survey, a link,
   a name taken), then each file to a temporary name, its mode and time
   set, and linked into place where nothing may be replaced or renamed
   over the config and `known_hosts`, whose times are kept. Each change is
   skipped when already made, so the script can run again. It prints
   `ok` or a failure that names no file.
4. **Verify**: a second survey. The files are as written, `ssh -G`
   resolves the entry to the detector on port 22, the account, and the
   key, no other `IdentityFile` anywhere names the key's path (compared
   after `~`, `%d`, `.`, and `..`) or varies by destination, and no agent
   holds it. Then the private key is dropped;
   it exists only on the bait laptop. A decoy that fails is taken off again
   and retired, and the reason given.

Each step is saved before the next. A step a retry could fix (the laptop or
the detector unreachable, a refusal to retire) leaves the operation for
`bufo resume`; a request to the detector keeps its id, so a repeat is
answered as done. Removing a decoy (`rotate`'s last steps, `unplant`)
surveys again and takes off only what is still as written: the exact
entry, the `known_hosts` line unless another entry looks the detector up
by the same name (a rotation's new decoy), and key files whose SHA-256
still matches. The write script's temporary file has the operation's own
random name, cleared at the start of each run, so a killed run leaves
nothing behind once it's resumed; key pairs made on the watcher are in
its state directory, cleared at the daemon's start. A detector asked to
arm a decoy it armed before checks the account and key line, and makes a
half-made one again, so a crash mid-arm resumes to an armed decoy.

Traces on the bait laptop: an SSH login from a watcher (logged at Info),
the owner's login shell and its startup files running `/bin/sh -s`, and
the files' change times. No Bufo file, binary, job, or record. Planting
can't be hidden from an intruder already in the bait laptop's account:
they can watch `~/.ssh` change, and the shell's startup files can watch
the command. Bait is planted when the bait laptop is believed clean, and
rotation after a trip assumes the intruder may see it. A host on the bait
laptop (Froggy Core) records the actor and an opaque operation id, never
what was placed; Bufo calls no host for it.

## 5. Watcher to watcher

**Reach.** A watcher listens on its tailnet address only, on a port root
there chooses (`bufo listen <address> <port>`), and tries again every 30 s
when the address goes. Root pins each peer on both sides with `bufo peer
add <address>`: one side makes the pair's pairing code and shows it once;
the other is given it with `--code`, typed at the terminal, never on the
command line. The side given `--port` dials, so a watcher that can't dial
is pinned without it and keeps the connection its peer opened; the dialer
reconnects with a backoff doubling to a minute, and a newer proven
connection replaces an older one.

**Authentication** (proposal: Froggy's mesh pattern, which is built and
used): Network.framework TLS with a pre-shared key per pair of watchers,
made at install, plus an HMAC over the session's exporter secret in the
first frame, and the source address checked against the pinned one. The
PSK identity is random per install. No handshake of Bufo's own.
Before authentication: one connection per pinned address, a 5-second
timeout for the handshake and the proof, and nothing parsed but the proof.
After: frames length-prefixed and capped (64 KB), JSON; a frame empty,
oversized, or malformed ends the connection. One batch of updates is in
flight per peer; the ledger bounds the rest.

**Tailscale whois** is evidence only: which node used a decoy. It is
deferred past Milestone 1 (the address is kept). The daemon never runs the
Tailscale CLI as root (it lives in a bundle the owner can replace); it will
speak LocalAPI itself, and when attribution fails it says unknown (E7).

**Messages.** Each watcher keeps a ledger: every incident it knows in its
newest revision, its recent alarms, each stamped as accepted, and each
recipient's cursor. It is written before anything is sent; a recipient
gets what is past its cursor, oldest first, until it acks. Delivery is at
least once and in order, and a recipient however far behind still gets
current state; one past the kept alarms sees the gap in their sequence. A
watcher sends a peer only its own updates, over one connection at a time
and in stamp order, so each watcher's alarms arrive in order; a host gets
everything.

- `update`: an incident's newest revision (the kind, the detecting
  watcher, the source, times, counts; never the placement, the account, or
  the fingerprint), or an alarm (7). A receiver's ledger takes only a
  newer revision of an incident, and each alarm once.
- `health`: every 60 s, and first on each connection: the watcher's id,
  daemon instance (boot session, start time), a sequence, detector
  coverage, last self-test, kinds on, and the latest alarm sequence. A
  peer's id is pinned from its first health; another later is refused.
  Configuration revision, tailnet state, and delivery health (6) come with
  hosts.
- `stopping`: sent on SIGTERM. The alarm still waits out the 5 minutes, so
  a restart or an update makes none, and then says the peer stopped.
- `plant` and `retire` (the planting grant, decided 2026-10-29, the
  owner): a planting watcher's public key and
  account name to arm, or a decoy of its own to retire; the only placement
  data that crosses, as the design's exception for cross-machine bait.
  Root at the detecting watcher grants this per peer when pinning it
  (`--may-plant`); the grant covers decoy accounts of the fixed shape (3),
  within the watcher's limit of 4, and a peer retires only those it armed.
  Answered with nothing or a refusal. Every other change still
  takes root at the watcher it changes.
- `ack`: through a ledger stamp, sent only once the receiver has saved
  what it acks; a sender sends only what it has saved.

Raw log lines (which name the account and fingerprint) stay on the
detecting watcher, root-only, as local evidence.

## 6. The host contract, and how Froggy attaches

**The package.** `BufoContract`, a product of this repository's root
package, with no dependencies. Froggy pins it by URL and exact revision
(proposal).

**The local transport.** The daemon's Mach service, in the system domain.
A host connects with `XPC_CONNECTION_MACH_SERVICE_PRIVILEGED` and sets
Bufo's requirement on the connection, so it talks to no impostor; the
daemon sets, on each incoming connection, one requirement that ORs the
pinned host requirements (the setter can be called once per connection),
checks its result before reading anything, then matches the caller's
audit token to a pinned (requirement, user) pair and serves only that
host's namespace. Bufo's requirement and Mach service name are the host's
own settings, since other builds of Bufo carry other teams.

**The API** (ARCHITECTURE, Hosts):

- `status`: installed, role, kinds on, coverage, peers' and delivery
  health. No placements. A host tells "not installed" (no Mach service)
  apart from "installed but unreachable, refused, or misconfigured", and
  shows the second as trouble.
- `updates(after:)` and a subscription: each update at least once, in
  order, from the ledger, past that host's cursor until it acks; the host acks
  only after it has stored the update durably. As built (step 7), the
  cursor is Bufo's and the subscription a long poll: `updates` returns up
  to 64 past the cursor, waiting up to 25 s for one, and `ack` moves it.
- `delivery(alarm, stage)`: the host reports each alarm's stages (stored,
  submitted to APNs, accepted by APNs, opened on the phone), which Bufo
  keeps as delivery health.
- `hostDecoy.register(id)` and `hostDecoy.presented(id, source)`: ids are
  scoped to the registering host and capped in number; a report for an id
  it didn't register is refused. Bufo stamps the time it received a
  report, keeps the host's identity on it, and marks its source as
  reported by that host, not observed. A lying host can raise alarms, from
  its own budget (7), and never contain.
- `cause(event)` (later): the answer ranks, never suppresses.

**The host credential, for Froggy.** Froggy's pairings are TLS PSKs, so
there is no token to hash at presentation. The decoy is a PSK identity and
key shaped like a real pairing's; Core keeps only the identity's hash in a
registry that can never admit a pairing. A client offering that identity
in its handshake trips: Core sees it in the PSK selection callback
(`sec_protocol_options_set_pre_shared_key_selection_block`, which on a
listener receives the client's offered identity, F1), declines exactly as for an unknown identity, and reports the
presentation. That proves the identity was presented, not that the key
was held, which is enough: only the bait has the identity.

## 7. Incidents, alarms, and health

- **An incident** is (decoy, source): the source is an address (a node
  once whois is in) or, for a host's report, the name the host gives,
  kept with the reporting host. It holds the kind, the detecting watcher,
  first and last seen, a count, connections, and local evidence (the first
  20 raw lines, on the detecting watcher only). Repeats merge; a new source
  opens a new incident. A decoy has at most 64 open incidents, and trips
  from further sources count on one whose source is unknown, so a flood of
  sources can't grow the store without bound. Closed incidents are kept;
  they grow only as root closes them.
- **Recording is never budgeted;** only alarms are. Every trip is counted
  and stored before any budget is consulted, and counters persist across
  restarts. Times are the watcher's own receipt times.
- **Alarms.** An alarm is a decision the owner should hear, numbered in its
  watcher's alarm sequence and carrying its incident as it stood, so a gap
  in the sequence is a lost alarm. An incident alarms when it opens; while
  open, again at the 10th and 100th trip, on a new connection after an
  hour's quiet, and at least daily as a reminder. At most 10 alarms an hour
  per budget: one for trips the watcher observed, one for each host's
  reports, one for health. An alarm over budget isn't sent; its incident is
  recorded and delivered all the same, an alarm each hour counts what was
  held back, and a held-back incident reminds like any other.
- **Closing.** By root at the watcher (`bufo close`), never by a host
  and never by quiet alone. An incident with no trip for 7 days
  stops reminding and stays open.
- **Delivery.** The detecting watcher tells its peers and its hosts; each
  peer tells its own hosts. A host may get one incident from two watchers;
  the incident's id makes them one. APNs is best effort and the owner can turn
  off time-sensitive notifications, so the phone is the last line, not the
  only one: hosts keep incidents for the phone to fetch when it connects.
- **Health.** A peer whose `health` stops for 5 minutes, or reports
  degraded coverage or a failed self-test, is a **silence alarm** from
  every peer that sees it: its own kind, one per spell, and one when it
  returns. A watcher counts a peer's silence only from its own start or
  last stall (frozen, or the machine asleep), so its own downtime is never
  the peer's silence (step 5's drill). A daemon told to stop (SIGTERM at shutdown or restart) first
  sends its peers `stopping`, so the alarm says it stopped rather than
  went silent; root could send the same, so it is still an alarm (decided
  2026-10-29, the owner). A network cut looks like silence. A watcher that
  can't dial out reports a peer's silence only through its own host.
- **Delivery health.** A watcher whose hosts take updates says in
  `health` whether one asked within 15 minutes (of now, or of its own start
  or stall) and didn't last report a failed stage; its peers alarm through
  their hosts when none did, once per spell, and when one does again. A
  host that has never taken updates (one that only reports) doesn't count,
  and a watcher with none says nothing (ARCHITECTURE, Delivery health).
  When every deliverer is down, only the phone can
  notice: **signed beacons** (proposal, M2) are each watcher's `health`
  summary with its latest alarm sequence, signed with the watcher's key,
  for hosts to carry. What the phone does with them is the host's.
- **Without a host,** incidents stay in the watchers' records and `bufo
  status` shows them.

## 8. Experiments

Run 2026-10-29 with throwaway tools, removed once the results were in
(`spikes/`, last in commit ed60249).

**Results, 2026-10-29** (Apple-silicon watchers on macOS 27.0.1, spikes
signed Apple Development with the hardened runtime):

- **E1** passes with someone logged in: a root LaunchDaemon made, reloaded
  from a file, and signed with Secure Enclave keys in every protection
  class, and did key agreement. The data protection keychain refused it
  (`-25291`, no keychain available). Before anyone logs in: skipped (the
  owner, 2026-10-29).
- **E3** passes in part. The root stream saw every sshd line; a program
  named `sshd-session` elsewhere logged identical text, told apart by its
  `processImagePath`, `processImageUUID` (the real one matches the binary
  on disk), and `userID`. sshd's Info lines lasted about 9 minutes in
  memory; default-level lines lasted hours.
- **E3b** passes: with `/Library/Preferences/Logging/Processes/
  sshd-session.plist` persisting Info, a trip's lines (fingerprint, PAM's
  refusal) and a self-test's were read back with `log show --info` 21
  minutes later, and every Info line since the file was written stayed;
  without it they were gone after about 9 minutes. Longer retention
  follows the persisted store's own limits, not measured.
- **E4** is moot: no session is ever opened (E5), so nothing is left to
  forward.
- **E5**: for both test accounts, in Remote Login's access group and out
  of it, sshd logged `Accepted key … SHA256:<fp> found at …` and
  `Postponed publickey`, then PAM refused the account (`pam_sacl` for the
  one outside the group; OpenDirectory's shell check, `/usr/bin/false`,
  for both), logged as `Failed publickey … SHA256:<fp>`; the client saw the
  connection closed. A wrong key for an existing account logs `Failed
  publickey` with its fingerprint; a name no account has logs only
  `Invalid user`. Hidden from the login window: not checked.
- **E6**: a `SpawnConstraint` naming another team stopped launchd from
  running the job (`last exit reason = OS_REASON_CODESIGNING`); the right
  team ran. The `SMAppService` replacement test wasn't run: the legacy
  path stands either way.
- **E8** passes: the second watcher reached a TLS-PSK listener on the
  first's tailnet address, and the first couldn't connect back. `ssh -F
  /dev/null` with a pinned host key wrote, renamed, and backdated a file on
  the bait laptop, which kept one Info `Accepted publickey` line per
  connection, the file's change time, and no `last` entry.
- **E9** passes: requirements held both ways; an ORed requirement admitted
  both identities; an ad-hoc copy and an unlisted identity of the same team
  were refused before any message was read.
- **F1** passes, against the SDK's description: on the listener, the PSK
  selection block is called with the identity the client offered, before
  any key is chosen. Declining it gives the client `unknown PSK identity`,
  exactly what an identity the server never had gives, while a known
  identity with the wrong key gives `bad MAC`. A host needs only the
  decoy's identity, not its key.

- **E10** (2026-10-30, step 6's drill; `scripts/e10.sh`): an intruder's
  comparison of every private key by what's readable without using any
  (passphrase, `.pub`, comment, mode, modification, creation, and inode
  change times, whether an entry names it, `known_hosts`, shell history,
  agents), a point for each way a key differs from most of its
  neighbours. On the drill account it picked a real key (the one with a
  passphrase) after each of five plants and rotations, and the decoy
  never. The decoy's one odd point each time was the newest inode change
  time, which only root can set; the drill account's real keys were made
  that day and backdated too, which hid what a laptop whose keys aged
  naturally would show: a decoy whose inode changed long after its
  modification time. That comparison stays (Principles, Age). Backdating
  the modification time moves the creation time with it, so that one
  doesn't show.

Not run: **E7**, LocalAPI `whois` from a root daemon, deferred with
whois.

## 9. Milestone 1

The alert-only SSH-key decoy on the first watcher and Froggy's credential
decoy, with their alarms reaching the hosts on both watchers, surviving the
failures below. Each
step stands on its own; the repository is in brackets.

1. **Experiments** [bufo]. Done 2026-10-29 (8).
2. **The package** [bufo]: `BufoContract`, `BufoKit`, `bufo`;
   `scripts/build.sh`; tests for the log parser (with forged-process and
   hostile-field fixtures), the trip matcher, incident merging and
   budgets, and the ledger. Exit: tests pass; `bufo status` with no
   daemon prints `{"installed": false}`. Done 2026-10-29; reworked after
   Codex Sol's review (alarms numbered apart from incidents, per-host
   budgets, bounded state, a ledger in place of outboxes).
3. **Install and the daemon** [bufo]: root file handling, per-install
   names, the plist with its constraint, state, the Mach service with
   `status` for the CLI, uninstall. Exit: on the first watcher, `status`
   answers; a swapped artifact, a symlinked destination, a lower version,
   and a failed install each leave the machine as it was; the daemon comes
   back after a restart once the watcher is unlocked; uninstall removes
   every file it made. Done 2026-10-29, drilled as root on the first
   watcher after Codex Sol's fifth round; a reused label, a non-root
   caller, and a newer update were drilled too. A failed install takes
   about 30 seconds, waiting out the daemon's answer before undoing.
4. **The detector** [bufo]: `arm` and `retire` by root at the watcher (the
   operations a planting peer will ask for in 5), the account, key line, sshd file, buffered
   stream with history, coverage, incidents and budgets, the self-test,
   configuration checks. Exit: a test key placed by hand on another
   machine trips one incident, from a remote address and through an SSH
   relay on the watcher itself; fifty repeats stay one incident with the
   alarms the budget allows; the owner's SSH logins are unaffected; the
   self-test passes for a day; killing the stream shows degraded coverage.
   Drilled 2026-10-29 on the first watcher, all but the day of
   self-tests: one remote incident, one through a relay on the watcher,
   fifty uses one incident with two alarms, a killed stream degraded until
   the next self-test, a stopped daemon's gap read back, uninstall leaving
   nothing. The drill dropped the logging preference (above) and showed
   that the stream and history report a line differently (Coverage).
5. **Two watchers** [bufo]: TLS-PSK peers, ledger delivery and acks, health,
   silence and degraded-coverage alarms, the plant grant. Exit: a trip on the first
   watcher reaches the second within 5 s; killing either daemon between
   storing and acking loses nothing; malformed and oversized frames are
   dropped; stopping the first watcher raises one silence alarm on the
   second within 6 minutes and one recovery.
   Drilled 2026-10-30 between the two watchers: a trip reached the second
   in under a second; a kill -9 on either side during a flood of trips
   lost nothing (every alarm taken, none unacked); garbage got a TLS alert,
   a connection that proved nothing was closed at 5 s with the next from
   that address held off until then, and an unpinned address got no answer;
   a frozen first watcher raised one `silent` at 5 minutes, a booted-out one
   one `stopped`, each with one `back` within a minute of returning. The
   drill removed two false alarms: a restart reading its gap called itself
   degraded, and a frozen watcher called its peer silent.
6. **Planting** [bufo]: survey, imitation, `plant` to the detector, writes,
   `rotate` as persisted states. Exit: from the second watcher, bait lands
   on the bait laptop and arms the first watcher; `ssh -G <alias>` resolves
   as the real entries do; using it trips; a crash mid-rotation resumes;
   nothing of Bufo is on the bait laptop; planting refuses a default
   identity name, a `Host *` `IdentityFile` that would offer the decoy, an
   agent holding it, and a laptop whose real keys all have passphrases;
   E10's script can't pick the decoy.
   Drilled 2026-10-30 from the second watcher onto a throwaway account on
   the bait laptop, made to look lived in (three keys, one with a
   passphrase; entries for a forge and both watchers), detected by the
   first watcher: a plant, four rotations, and an unplant. The decoy
   copied the entry for the detector the laptop already reached, as a
   second account there, and its key a real key's name, comment, modes,
   and a time among theirs; `ssh -G` resolved it as the real entry did;
   using it reached the second watcher as an alarm in under a second; a
   rotation with the daemon killed mid-plan and one with the CLI killed
   were each resumed to the end; unplant left the config and
   `known_hosts` byte for byte as before and nothing else of Bufo there.
   The refusals are tested, not drilled. The drill found that a root
   daemon can't remove a local account without Full Disk Access (macOS
   refuses it as "disallowed by sandbox"; `sysadminctl` wants an
   interactive authorization), so arming now takes it; and that the
   daemon's own user lookups kept an account it had just removed, so
   accounts are looked up in new processes. The grant survived `update`.
7. **Hosts** [bufo]: per-host namespaces, ledger cursors, decoy registration and
   reports, delivery stages; a test host under `Tests/`. Exit: the test host
   gets every incident at least once across its own restarts and acks;
   another app, or the right app as another user, is refused; a host can't
   report an id it didn't register. Built 2026-10-30: `host add|remove`; the
   service takes Bufo's requirement or any host's on each connection and
   names the caller per message by its code signature and user; the client
   (`BufoService`) is in the contract; `Tests/TestHost`, signed by `make
   build` under its own identifier, stores each batch before acking.
   Delivery stages are kept and shown; delivery health came with step 8.
   Drilled 2026-10-30 on the second watcher, the test host pinned for one
   user: as root and as another user it was refused, and an ad-hoc signed
   copy of it never reached the daemon; it registered a decoy, a report of
   an id it hadn't registered was refused, and one it had opened an
   incident under its name that the first watcher took as well. Following
   updates, it was killed with `-9` after its first batch; trips on the
   first watcher while it was down and while it followed again all reached
   it once restarted, each alarm once and each incident at its newest
   revision, and it ended with nothing unacked.
8. **Froggy** [froggy; the owner schedules it]. Exit: a trip on the first
   watcher reaches the second watcher's Commander as an alarm; presenting
   the decoy PSK identity to a watcher's Core opens an incident.
9. **Drills and docs** [bufo]: README describes what ships; ARCHITECTURE
   records the decisions. Drills: a trip, repeats, a silence, a rotation,
   the second watcher cold-booted with no one logged in, the first
   watcher restarted and left locked until unlocked by hand, and the bait
   laptop's Commander off throughout, and a person on the bait laptop
   trying to pick out the decoy without using it. Exit: each drill ends in the alarm
   it should; no Bufo interface (CLI, XPC, peer message) carried a
   placement beyond the `plant` message's own (5). sshd's own log lines do, on the detecting watcher; that is
   the operating system's trace, documented.

**Later milestones**, following ARCHITECTURE's Order:

- **M2** Signed beacons for hosts to carry, cause queries, and, only if
  the owner wants changes from elsewhere, pinned keys and a signature
  check (ARCHITECTURE, Root at the watcher).
- **M3** Security evidence kept off the source watcher, redacted; raw
  lines leave only by root at the source.
- **M4** Developer ID signing and notarization; the store under the Secure
  Enclave key (2).
- **M5** The collector (Endpoint Security system extension, after an
  `eslogger` prototype), then whois attribution, cause ranking, ports,
  wallet folders, scheduled rotation and rotation after trips,
  containment with its own signed authority, and the hardware detector
  moving in from Froggy.

## Concerns with the design as decided

- **The bait laptop's real credentials reach the watchers.** If the bait
  laptop holds an SSH key or a Froggy pairing that opens the owner's
  account on a watcher, an intruder there can, without root: find the
  decoy account on the detecting watcher (2), quit the hosts that deliver
  alarms while every Bufo daemon stays healthy, and turn off Tailscale.
  Root-only state holds; detection and delivery don't. Signed beacons
  (M2) would let the phone catch the silenced delivery; nothing catches
  the identified decoy. Never typing a watcher's password on the bait laptop
  is the floor.

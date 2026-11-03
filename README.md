<p align="center">
  <img src="favicon.svg" alt="bufo" width="128" />
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> ·
  <a href="#commands">Commands</a> ·
  <a href="ARCHITECTURE.md">Architecture</a> ·
  <a href="PLAN.md">Plan</a>
</p>

# bufo

Bufo is a tripwire for your own computers. It plants decoys, things an
intruder would want and you never touch, and raises the alarm from a
different machine than the one they sit on.

```text
bait laptop            first watcher           second watcher
  ~/.ssh  --decoy used-->  sshd's log  --alarm-->  peer  --> your phone
  (runs nothing)          (detects)               (watches the first)
```

Anything running on a machine an intruder holds, the intruder can stop. So
the bait laptop runs nothing of Bufo, and the watchers that notice a trip
are machines the intruder doesn't hold. They watch each other too: a
watcher that goes quiet is an alarm of its own.

- **Nothing on the bait.** Bufo plants over SSH and leaves only the decoy,
  made to look like what is already there; the laptop runs nothing of
  Bufo's.
- **Decoys that look lived in.** Each decoy is copied from the laptop's own
  keys and entries: their names, comments, modes, and times. No name, path,
  or shape comes from the code, so the code can't give one away.
- **Alarms from elsewhere.** A decoy trips on another machine, which reads
  it in sshd's own log, so wiping the laptop doesn't hide the trip.
- **Watchers watch each other.** Peers trade incidents, alarms, and health
  over TLS. A peer that goes silent, loses coverage, or stops delivering is
  an alarm, and so is its recovery.
- **Root-only, agent-free.** Each watcher keeps its state where only root
  can read it. No output names a decoy, and no agent or MCP tool reads or
  changes Bufo.
- **Standalone.** Bufo works on its own. A host app links its contract to
  deliver alarms and plant decoys of its own; Froggy is the first.

Bufo catches use inside your own network. A credential copied off a machine
and used somewhere else never reaches it; canarytokens (canarytokens.org,
or self-hosted) catches that, and Bufo is meant to run alongside it.

Bufo is pre-release: Milestone 1 is being drilled (`PLAN.md`), and there
are no published builds. You build it yourself, signed as you.

## Quickstart

You need two Macs to watch (macOS 15 or later, on one tailnet), a bait
laptop they can reach over SSH, and a Swift toolchain with an Apple
Development identity in the keychain.

```sh
make test
make build        # signed, in .build/bufo-signed/bufo
```

Before running a `bufo` you fetched with `sudo`, check it yourself; nothing
on the machine can do that for you: `codesign --verify --strict bufo`, then
`codesign -dv bufo` for the team and identifier you expect.

Install on both watchers. Bufo has no names of its own: choose a path,
label, and service that suit each machine.

```sh
sudo .build/bufo-signed/bufo install --binary <path> --state <directory> \
  --label <label> --service <name>
```

On the first watcher, which detects, listen and pin the second. It prints a
pairing code once:

```sh
sudo <installed binary> listen <its tailnet address> <port>
sudo <installed binary> peer add <second's tailnet address> --may-plant
```

On the second watcher, pin the first and type that code:

```sh
sudo <installed binary> peer add <first's tailnet address> --port <port> --code
```

Give the first watcher's installed binary Full Disk Access (below, under
`arm`). Then, from the second watcher, as the account that reaches the
laptop over SSH, plant:

```sh
sudo <installed binary> plant ssh-key --bait <you@laptop> --detector <first's tailnet address>
```

`status` on either watcher shows the decoy armed, coverage, and the peer.
To hear alarms on your phone, pin a host such as Froggy with `host add`.

## Commands

Every command prints one JSON object, or `{"error": …}` and exits nonzero.

### Install

- `sudo bufo install --binary <path> --state <directory> --label <label>
  --service <name>` installs this build as a LaunchDaemon. You choose every
  name. The binary's directory must be one only root can change; install
  makes it if its parent is. The state directory must not exist yet.
  Install writes the binary, its config beside it as `<binary>.json`, the
  state directory, and the job's plist in `/Library/LaunchDaemons`, and
  returns once the daemon answers. If any step fails, it removes what it
  made.
- `bufo status`, run from the installed binary, asks the daemon; any other
  copy prints `{"installed":false}`.
- `sudo <installed binary> update <artifact>` replaces the installed build
  with a newer one of the same team and identifier, and puts the old one
  back if the new one doesn't answer.
- `sudo <installed binary> uninstall` stops the job, retires every decoy,
  and removes every file install and arming made. It doesn't reach bait
  laptops: unplant first.

### Decoys

- `sudo <installed binary> arm <account> <public key file>` arms an SSH
  decoy on this watcher: a new hidden account with no password and
  `/usr/bin/false` for a shell, outside Remote Login's access group, whose
  home in `/Users` authorizes only that key and only to run
  `/usr/bin/false`. The first decoy also adds a file to
  `/etc/ssh/sshd_config.d` setting `LogLevel VERBOSE`. sshd checks
  the key and logs it, PAM refuses the account, and the daemon, reading
  sshd's log, opens an incident for each source that uses the key. At
  most 4 decoys at once. You place the private key yourself (or `plant`
  does); anyone who offers it to this watcher's sshd trips it. macOS lets
  only a process with Full Disk Access remove a local account, so arming
  refuses until the installed binary has it (System Settings → Privacy &
  Security → Full Disk Access → +; in the file picker, ⌘⇧G and the
  binary's folder, then the binary), and `status` notes when it's missing.
- `sudo <installed binary> retire <account>` removes a decoy's account; its
  incidents stay open. Retiring the last one removes sshd's file too.

### Watchers

- `sudo <installed binary> listen <tailnet address> <port>` has this
  watcher listen for peer watchers there.
- `sudo <installed binary> peer add <tailnet address> [--port <port>]
  [--may-plant]` pins another watcher. Run it on both: on the first it
  prints a pairing code once; on the second, add `--code` and type that
  code when asked. The side given `--port` dials the other there. Peers
  trade incidents, alarms, and health over TLS with that code's key; a
  peer unheard for 5 minutes, or reporting degraded coverage, is an alarm,
  and so is its recovery. `--may-plant` lets that peer arm up to the same
  4 decoys here and retire the ones it armed, nothing else.
  `peer remove <tailnet address>` unpins it.

### Planting

- `sudo <installed binary> plant ssh-key --bait <[user@]host> --detector
  <tailnet address>` plants an SSH decoy on a bait laptop, a Mac that runs
  nothing of Bufo, detected by this watcher (its listening address) or by
  a peer that granted `--may-plant`. Run it with sudo from the account
  that reaches the laptop over SSH: Bufo connects as you, with no ssh
  config, and the first time asks you to confirm the laptop's host key,
  which it then pins. It reads the laptop's `~/.ssh`, makes a key and a
  `Host` entry copied from what is there (the real keys' type, size,
  format, name, comment, modes and times; a real entry's options, case,
  and indentation; a `known_hosts` line if the real entries have them),
  arms the decoy's account on the detector, writes the files, and checks
  that `ssh -G` resolves the entry and nothing else would offer the key
  (an agent on the laptop that doesn't answer within 5 seconds holds
  nothing).
  It refuses a laptop it can't imitate: fewer than two private keys, every
  key with a passphrase, keys all named as OpenSSH's defaults, an
  `IdentityFile` that varies by destination, no `Host` entry with a `User`
  to copy, or no user name to copy for the account. The private key is
  never kept once it's written.
- `sudo <installed binary> rotate <[user@]host>` plants a new decoy there
  and then removes the old one from the laptop and retires it;
  `unplant <[user@]host>` only removes and retires. Each step is saved, so
  if one is interrupted (the laptop or the detector unreachable, a crash),
  `sudo <installed binary> resume` carries on. A decoy that fails its
  check is removed again. Removal takes off only what is still as written.

### Hosts

- `sudo <installed binary> host add <name> --requirement <code
  requirement> --user <account>` pins an app on this Mac as a host: only
  that app, signed as the requirement says and run as that account, may
  call as `name`. A host links `BufoContract` and, through `BufoService`,
  reads `status`, takes every incident and alarm this watcher knows (its
  own and its peers') in order, at least once, acking each batch once it
  has stored it, reports how far it delivered each alarm, and registers up
  to 16 decoys of its own (a host credential) and reports their use, which
  opens incidents in its name, under its own alarm budget. A report for a
  decoy it didn't register is refused, and its ids never meet another
  host's. `host remove <name>` unpins it. Once a host has taken updates,
  this watcher counts it as delivering while it asks at least every 15
  minutes and its last reported stage isn't a failure; when no such host
  is delivering, the watcher's peers alarm through their own hosts, and
  again when one is.

### Status

- `status` shows whether decoys are armed, coverage (`full`, `degraded`
  with a note saying why, or `off`), the last self-test (a throwaway key
  offered to sshd every few hours for one of macOS's own service accounts,
  which must come back through the log), open incidents by kind (this
  watcher's and its peers'), and each peer: connected, last heard, its
  coverage, and updates it hasn't acked, how many decoys this watcher
  has planted, and each host: last heard, last ack, what it hasn't acked,
  and the last delivery stage it reported, and whether the hosts that
  take updates are delivering. No output names a decoy.

## Learn more

- [Architecture](ARCHITECTURE.md) — the design and its decisions: roles,
  decoy kinds, what a trip is, protecting Bufo, and hosts
- [Plan](PLAN.md) — the work, milestone by milestone, and what each drill
  found
- [Agents](AGENTS.md) — the rules for working in this public repository

MIT licensed; see `LICENSE`.

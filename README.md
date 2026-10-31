# Bufo

Bufo watches your own computers for untrusted use. It plants decoys, things
an intruder would want and you never touch, and watches for them being used
from a different machine than the one they sit on.

Bufo catches use inside your own network. A credential copied off a machine
and used somewhere else never reaches it; canarytokens (canarytokens.org,
or self-hosted) catches that, and Bufo is meant to run alongside it.

Bufo installs as a daemon that watches for SSH decoys, plants them on a
bait laptop over SSH, and trades alarms with other watchers. The design is
in `ARCHITECTURE.md` and the work in `PLAN.md`. `make test` runs the tests; `make build` builds a signed `bufo`.

Before running a `bufo` you fetched with `sudo`, check it yourself; nothing
on the machine can do that for you: `codesign --verify --strict bufo`, then
`codesign -dv bufo` for the team and identifier you expect.

Every command prints one JSON object, or `{"error": …}` and exits nonzero.

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
  that `ssh -G` resolves the entry and nothing else would offer the key.
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
- `status` shows whether decoys are armed, coverage (`full`, `degraded`
  with a note saying why, or `off`), the last self-test (a throwaway key
  offered to sshd every few hours for one of macOS's own service accounts,
  which must come back through the log), open incidents by kind (this
  watcher's and its peers'), and each peer: connected, last heard, its
  coverage, and updates it hasn't acked, how many decoys this watcher
  has planted, and each host: last heard, last ack, what it hasn't acked,
  and the last delivery stage it reported, and whether the hosts that
  take updates are delivering. No output names a decoy.
- `sudo <installed binary> uninstall` stops the job, retires every decoy,
  and removes every file install and arming made. It doesn't reach bait
  laptops: unplant first.

MIT licensed; see `LICENSE`.

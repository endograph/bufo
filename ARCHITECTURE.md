# Bufo Architecture

Decided 2026-10-29, the owner, starting from Froggy's tripwire design (one
review round with Codex Astra); Milestone 1 is being built (`PLAN.md`). Bufo tells the owner when
something untrusted uses the owner's machines, and adds nothing to ordinary
use. It runs on macOS first.

Terms: a **decoy** is something planted for an intruder to use; its
**placement** is what it became on one machine (path, name, port, key
material); a **detector** notices a decoy being used; a **trip** is one
such use, and an **incident** gathers a trip and its repeats. A **host** is
an app that uses Bufo when present (Froggy first).

## Principles

- **Built for signed v1.** The design assumes Developer ID signing with the
  hardened runtime and notarization. What is marked *(v1)* holds only for
  such builds; work done before then is designed as if it holds.
- **The mechanism is public, the placements are secret.** The code says how
  decoys imitate and never what one became. Placements are generated from
  the bait machine's surroundings and randomness the watcher makes and
  keeps in its store; there is no owner-wide seed, since one would reveal
  every placement, past and future, on every machine (decided 2026-10-29,
  the owner):
  - *Imitation.* A decoy copies the shape of the real things around it:
    the machine's host naming, key naming, config style and order, and the
    ports its network actually uses. Nothing comes from a list in the code,
    since an intruder can check against a published list.
  - *Age.* A decoy looks as old and as used as its neighbours: backdated
    modification times, and the traces a real one leaves (a `known_hosts`
    line, its place in `~/.ssh/config`). The inode change time can't be
    faked without root; a careful intruder could compare it.
  - *Comparison.* Published honeytokens were caught by facts an intruder
    could compare, not by their code being public. A decoy must survive
    every comparison with its real neighbours: whether they have
    passphrases or live in an agent or the Keychain rather than in files,
    whether they are published somewhere it isn't (a forge's public key
    list), a `.pub` file and its comment, `known_hosts`, shell history that
    names them and never it, times, and how few neighbours there were to
    copy. Each kind lists the comparisons it must survive, and planting
    refuses a machine where it can't match one rather than invent.
  - *Rotation.* Placements are replaced periodically and after every trip.
- **Trip on use, not on reading.** Agents, Spotlight, backups, and
  antivirus read everything, so a decoy trips when a credential is used or a
  listener is reached. Decoys that trip on an open go only where nothing
  legitimate reads, and need the collector.
- **Bait on one machine, detector on another.** The strongest decoys are
  taken on one machine and detected on another, so the alarm comes from a
  machine the intruder doesn't hold, and tampering with the bait's machine
  doesn't silence it.
- **Each kind declares its network.** A decoy kind states what it assumes
  of the network between the owner's machines, and Bufo turns it on only
  where that holds. The first network is a Tailscale tailnet: nothing
  legitimate scans it, only members reach a machine, and a source address is
  a WireGuard-authenticated node, which names the peer that connected (it
  may be relaying for another). Listeners bind to the tailnet address and
  close when it goes. A decoy port on a home LAN would trip on Bonjour and
  printers; another network gets its own set.
- **Alongside canarytokens, not instead.** Bufo catches use inside the
  owner's network, with the alarm raised on a machine the owner holds. A
  credential copied off and used from elsewhere, the usual path for an
  infostealer's haul, never reaches a watcher. Canarytokens (hosted, or
  self-hosted) catches that, and Bufo doesn't duplicate it (decided
  2026-10-29, the owner).

## Roles

- **Bait-only.** A machine that only holds bait runs nothing of Bufo: no
  process, launchd job, system extension, or file of its own. Its decoys are
  inert files, watched from elsewhere, so an intruder who searches it finds
  no Bufo. The machine most likely to be compromised (the one with the
  browser and the agents) should be bait-only. Rotation there is an
  occasional job a watcher runs.
- **Watcher.** A machine that runs Bufo's detectors, and optionally its
  collector and hardware detector. Its state is root-only, so an intruder
  running as the owner (the common case: an infostealer) can see that Bufo's
  process exists, since macOS shows every user's processes, but can't read
  what it knows. What it plants outside its state can still be seen: an SSH
  decoy's account is in Directory Services and its name in sshd's log
  lines, both readable by the owner's admin account, so an intruder who
  holds the owner's account on the detecting watcher can tell the decoy
  (found 2026-10-29, Codex Astra's review). A detecting watcher's daemon
  has Full Disk Access, granted by the owner by hand: macOS lets a root
  daemon create a local account but removes one only for a process with
  it, so without it no decoy could be retired (found 2026-10-30, step 6's
  drill). Its process name, launchd label, and paths are chosen per
  install, which stops scripted checks and nothing more.
- **Visible where it runs.** A decoy kind that needs Bufo on its own
  machine (one that trips on an open, the collector, the hardware detector)
  makes that machine a watcher, and is taken on per machine knowing that.
  Bufo never hides from root: on macOS with SIP that is rootkit work, it is
  what malware does, and it would stop the owner auditing their own machine.
  Being seen is a deterrent: an intruder who finds Bufo knows some
  credentials are traps, not which, and one who then avoids every credential
  was stopped without a trip.

## Decoy kinds

- **SSH key** (first release). The private key, with no passphrase, and a
  `Host` entry in `~/.ssh/config` go on a bait machine. The public key goes
  in a watcher's `authorized_keys` for a dedicated unprivileged account, as
  `restrict` with a protected forced command. The trip is that key's
  fingerprint being accepted (sshd at `VERBOSE`, or `openssh_login`), not
  the forced command running, since a client can authenticate without
  opening a session. `openssh_login` carries the account and source but no
  fingerprint, so it names the decoy only by its account (checked against
  the macOS 27 SDK, 2026-10-29). On macOS the account never gets a
  session: PAM's account check refuses an account whose shell is
  `/usr/bin/false`, after sshd has checked the key and logged its
  fingerprint (`Accepted key … found at`, then `Failed publickey`), so the
  forced command is only a backstop (tested 2026-10-29). sshd logs at
  Info level, which macOS keeps only in memory, for minutes, so a detector
  down for longer can't read its gap back: that is degraded coverage, and a
  silence its peers alarm on. A per-process logging preference would keep
  Info on disk (tested 2026-10-29), but a LaunchDaemon can't write it
  (step 4's drill), so Bufo doesn't set one. The owner's own `ssh` never offers the
  key, since a refused offer of it trips too: its file is never one of
  OpenSSH's default identity names, no other `Host` entry and no agent
  offers it, and planting and every rotation check that (decided
  2026-10-29, the owner).
- **Host credential** (first release). A token shaped like a host's real
  credential that authorizes nothing. The host holds only its hash and
  reports anyone presenting it (Hosts). A host like Froggy is the service an
  intruder on the owner's network would most want, and only the host checks
  its own credentials.
- **Ports** (later). Listeners on ports a scan tries that nothing on the
  network uses, checked against what listens there.
- **Wallet folders** (later). Paths infostealers enumerate, excluded from
  Spotlight. They trip on an open by an unexpected process, so they need
  the collector, and they're noisier: backup tools and antivirus read them,
  and process names can be spoofed.
- **Hardware** (later, moving in from Froggy's Device Tripwire). New
  displays, keyboards, and USB devices lock the screen, displays the owner
  attached when arming excepted. It needs Input Monitoring and runs on its
  own machine, so that machine is a watcher.

## A trip

- **Incident.** The detecting watcher records the trip: the decoy kind
  (never its placement), the machine, the source (a tailnet node, or a
  process instance with its signing identity), the time, and any cause a
  host reports. One incident per decoy and source collects repeats, with a
  budget for notifications and evidence, so poking a decoy over and over
  makes one alarm, not a flood.
- **Alarm.** The watcher tells the other watchers and every subscribed host.
  A host delivers it to the owner (Froggy pushes to the phone as a
  time-sensitive alarm). Without a host, an alarm stays in the watchers'
  records and the watcher's own notifications; reaching a phone takes a
  host. More than one deliverer is needed: with a single one, compromising
  it silences every alarm.
- **Silence.** Watchers send each other their health every minute; one
  quiet for 5 minutes is a silence alarm from the peers that notice it,
  its own kind, one per spell and one when it returns. A daemon being
  stopped (a shutdown or restart) tells its peers first, so the alarm says
  it stopped rather than went silent; root could send the same, so it is
  still an alarm (decided 2026-10-29, the owner).
- **Delivery health.** A watcher whose hosts take updates says in its
  health whether they are delivering: one asked within 15 minutes and
  didn't last report a failure. A host's asking is the signal, not its
  acks, so a quiet week isn't an outage. A host that only reports, like
  Core with its own decoy, delivers nothing and counts for nothing; a
  watcher with no host taking updates says nothing, since its peers'
  hosts deliver for it. When its hosts stop, its peers alarm through
  theirs, once per spell and again when delivery returns (decided
  2026-10-30).
- **Explained is not trusted.** A cause a host reports (an agent session,
  input just before) is shown with the trip and never suppresses it. An
  agent trying a credential it found is what a prompt injection looks like.
  Cause matching later ranks unexplained security events; it never silences
  high-value ones.
- **The first release only alerts.** Containment comes later, with its own
  authority:
  - Automatically, only the implicated peer is restricted on watchers
    (refused at the firewall and sshd), and each subscribed host restricts
    it in its own terms. Anything broader takes the owner's signature,
    which brings in the signature check (Protecting Bufo, Root at the
    watcher).
  - **That was me** signs the exact incident, the machines, the action, a
    nonce, an expiry, and the containment's revision, and each watcher and
    host checks the signature itself.
  - Kill binds to a process instance, not a PID.
  - Revoking SSH keys or tailnet access stays with the owner.

## Protecting Bufo

- **Local only.** Each watcher knows only the decoys it detects, and nothing
  about placements travels between machines. Two exceptions: the alarm
  (that decoy is spent and rotates), and placing a cross-machine decoy's
  bait. Bait reaches a bait-only machine from a watcher over SSH, as the
  owner with their own access, which need not be the detecting watcher
  (built 2026-10-30, `PLAN.md` 4): the watcher's daemon runs the operation
  and keeps it, the CLI carries its scripts there with the machine's host
  key pinned, and every choice copies what the survey found there or
  refuses. It leaves an SSH login, the owner's shell starting, and the
  files' change times, and nothing of Bufo; a host on that machine records
  the real actor and an opaque operation id, never what was placed.
- **The placement store.** Root-only files, encrypted under a Secure
  Enclave key with no user presence, since Bufo uses it unattended, whose
  sealed form is a root-only file beside them (decided 2026-10-29, the
  owner). It replaced a key in the data protection keychain under Bufo's
  own access group: Apple excludes launch daemons from that keychain
  (TN3137), and an app group serves as an access group on macOS only with a
  provisioning profile.
  - No keychain prompt exists to let another app in, and a Terminal with
    Full Disk Access reads nothing: Full Disk Access is TCC, not Unix
    permissions.
  - The sealed key is useless off its Secure Enclave, so a backup or a
    copied file decrypts nothing. It is bound to the machine, not to Bufo's
    signature, so any root process on that watcher can use it while there;
    the design already draws its line at root.
  - A root daemon makes, reloads, and uses such a key while someone is
    logged in (tested 2026-10-29); before anyone logs in is unverified
    (`PLAN.md`, E1); if it doesn't, the key is a random key in
    the same root-only file, and Bufo says so.
  - The key never leaves the Secure Enclave, so an intruder who runs as
    Bufo can use it only while inside, and loses the rotated placements
    after. *(v1)*
  - Losing the Secure Enclave (a logic board) means new placements, nothing
    more. A Mac without one (Intel without T2) keeps a random key in the
    root-only file, and says so.
  - What remains: anything that can sign as the team. The signing key stays
    off the machines where agents run, or in hardware. Bufo holds placements
    in memory to detect, so only the hardened runtime guards that. *(v1)*
- **Root at the watcher is the only authority** (decided 2026-10-29, the
  owner). Planting, rotating, closing an incident, updating, and
  uninstalling take root on that watcher; nothing shows a placement. A host
  reads status and incidents and reports its own decoy, and never changes
  Bufo, so compromising a host doesn't open Bufo. Bufo knows nothing of
  phones, pushes, or approvals: asking the owner is the host's. A watcher's
  password is typed only at that watcher, never on a machine it watches.
  If changes from elsewhere are wanted later, Bufo's part is only public
  keys pinned at install and a signature check over a fixed format; the
  host does the asking. This replaced verifiers pinned at install, whose
  signature every view and change took.
- **The planting grant**, the one change a peer makes (decided 2026-10-29,
  the owner). The watcher that reaches the bait may not be the one that
  detects it, so root at the detecting watcher, pinning a peer, may let it
  arm SSH decoy accounts of the fixed shape, a few at most, and retire the
  ones it armed; nothing else. A compromised peer can make only more
  useless decoy accounts.
- **Reading the store is a trip.** Any process other than Bufo opening it
  trips, once the collector can see opens.
- **No agent surface.** No agent or MCP tool reaches Bufo, and its JSON CLI
  never shows placements.

## The collector (later)

- **Source.** A prototype runs `eslogger` as root with Full Disk Access. It
  is not an API: its schema may change, it lacks a system extension's
  integrity protection, it hides its own process group, and it only
  notifies. `tcc_modify` needs macOS 15.4. v1 is a native Endpoint Security
  system extension, which needs Apple's Endpoint Security entitlement. The
  root part is fixed: authenticated output, bounded buffers, no commands or
  paths a caller chooses.
- **Events.** `openssh_login`, `login_login`, `lw_session_unlock`,
  `screensharing_attach`, `sudo`, `su`, `authentication`,
  `authorization_petition`, `btm_launch_item_add`, `profile_add`,
  `tcc_modify`, `get_task`, `get_task_read`, `remote_thread_create`, opens
  of decoy paths, and its own lifecycle. Raw exec and open events stay on
  the machine for a short time; security events go into the record.
- **Health.** A heartbeat proves a process answers, not that the sensor
  works. The collector reports its lifecycle, sequence progress (`seq_num`
  gaps), and restart identity, and another watcher checks the deadlines. A
  watcher going silent is its own alarm, distinct from a trip.
- **Evidence.** Another watcher keeps security facts under its own
  retention, beyond anything the source can delete, over a narrow
  authenticated channel. A trip is accepted only from a watcher pinned at
  install. A snapshot taken on a machine where root was lost is untrusted.

## Hosts

Bufo publishes a small contract package; a host links only that, and Bufo
imports nothing of the host's. Through it a host can:
- **Subscribe to incidents**, to deliver alarms and contain itself.
- **Read status** (installed, role, kinds on, health) with no placements.
- **Plant its own decoy**: the host credential, of which the host keeps only
  the hash and reports presentations.
- **Answer cause queries**: what, if anything, the host recorded as the
  cause of an event, used only to rank.

A host without Bufo works as before and says Bufo isn't installed. Froggy is
the first host: its side is in Froggy's `docs/ARCHITECTURE.md`, Bufo.

## Order

1. The SSH key decoy, detected on a watcher, and Froggy's host credential.
   Alerts only, as incidents.
2. The host contract with Froggy: alarms to the phone, from more than one
   deliverer.
3. Security evidence kept off the source machine.
4. v1 signing, then the placement store's keys.
5. The collector; then cause ranking, ports, wallet folders, rotation,
   containment, and the hardware detector moving in from Froggy.

## Rejected

- Containment across every machine on any trip: one compromised machine
  could set it off at will.
- Decoys that trip on reading where agents go.
- Decoy names, paths, or shapes from pools in the code.
- Decoys that trip off the owner's network, including third-party
  canaries such as an AWS key: canarytokens does that, and its alarm leaves
  the owner's network (Principles).
- Planting shell history that names a decoy, for believability: the
  owner's own history search would run it.
- Hiding from root.
- One owner-wide seed for placements: one secret that reveals every
  placement, past and future, and has to be carried into every machine.
- Keeping placements secret by gating the view alone, or keeping them in the
  login keychain, whose prompts the owner can be phished into approving.
- A package inside Froggy: Bufo is smaller to trust as its own signed
  product, keeps root and Full Disk Access out of Froggy Core, and can be
  published.

## Open

- Delivery against the intruder the design expects: a deliverer on the
  bait-only machine counts only against failures, and if that machine's
  credentials open the owner's account on a watcher, every host that
  delivers can be stopped while Bufo stays healthy. `PLAN.md` proposes
  signed beacons the phone times itself.

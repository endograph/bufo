# Bufo Architecture

Decided 2026-10-29, the owner, starting from Froggy's tripwire design (one
review round with Codex Astra); not built. Bufo tells the owner when
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
  decoys imitate and never what one became. Placements are generated on
  each machine from its surroundings and the owner's private seed, which
  never enters the repository:
  - *Imitation.* A decoy copies the shape of the real things around it:
    the machine's host naming, key naming, config style and order, and the
    ports its network actually uses. Nothing comes from a list in the code,
    since an intruder can check against a published list.
  - *Age.* A decoy looks as old and as used as its neighbours: backdated
    modification times, and the traces a real one leaves (a `known_hosts`
    line, its place in `~/.ssh/config`). The inode change time can't be
    faked without root; a careful intruder could compare it.
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
  what it knows. Its process name, launchd label, and paths are chosen per
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
  opening a session.
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
- **Third-party canaries** such as an AWS key (later, maybe). They catch
  use days later from anywhere, but alarm by email or webhook, outside the
  owner's network.

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
- **Explained is not trusted.** A cause a host reports (an agent session,
  input just before) is shown with the trip and never suppresses it. An
  agent trying a credential it found is what a prompt injection looks like.
  Cause matching later ranks unexplained security events; it never silences
  high-value ones.
- **The first release only alerts.** Containment comes later, with its own
  authority:
  - Automatically, only the implicated peer is restricted on watchers
    (refused at the firewall and sshd), and each subscribed host restricts
    it in its own terms. Anything broader is approved by a verifier.
  - **That was me** signs the exact incident, the machines, the action, a
    nonce, an expiry, and the containment's revision, and each watcher and
    host checks the signature itself.
  - Kill binds to a process instance, not a PID.
  - Revoking SSH keys or tailnet access stays with the owner.

## Protecting Bufo

- **Local only.** Each watcher knows only the decoys it detects, and nothing
  about placements travels between machines. Two exceptions: the alarm
  (that decoy is spent and rotates), and placing a cross-machine decoy's
  bait. *Open:* how bait reaches a bait-only machine (a one-shot run there,
  or a watcher over SSH) and what trace that leaves; a host on that machine
  records the real actor and an opaque operation id, never what was placed.
- **The placement store.** Root-only files, encrypted under a Secure
  Enclave key kept in the data protection keychain in Bufo's own access
  group, `AfterFirstUnlockThisDeviceOnly`, with no biometry, since Bufo
  uses it unattended.
  - No keychain prompt lets another app in, and a Terminal with Full Disk
    Access reads only ciphertext.
  - The key never leaves the Secure Enclave, so an intruder who runs as
    Bufo can use it only while inside, and loses the rotated placements
    after. *(v1)*
  - Losing the Secure Enclave (a logic board) means new placements, nothing
    more. A Mac without one (Intel without T2) uses the data protection
    keychain alone, and says so.
  - What remains: anything that can sign as the team. The signing key stays
    off the machines where agents run, or in hardware. Bufo holds placements
    in memory to detect, so only the hardened runtime guards that. *(v1)*
  - *Unverified:* whether an unsandboxed Developer ID app gets the data
    protection keychain with only an app-group entitlement and no
    provisioning profile.
- **Verifiers are pinned at install.** Installing Bufo on a machine pins the
  public keys of the owner's verifiers (a phone's approval key, a Touch ID
  Mac's key), approved on that machine. Viewing or changing anything takes a
  signature from one of them, never a password, which is what a stealer
  phishes. A host may carry the request and the signature, but can't add a
  verifier, so compromising the host doesn't open Bufo.
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
- **View and change**, carrying a request to a verifier and its signature
  back.
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
- Hiding from root.
- Keeping placements secret by gating the view alone, or keeping them in the
  login keychain, whose prompts the owner can be phished into approving.
- A package inside Froggy: Bufo is smaller to trust as its own signed
  product, keeps root and Full Disk Access out of Froggy Core, and can be
  published.

## Open

- How bait reaches a bait-only machine, and the trace it leaves (Protecting
  Bufo, Local only).
- The license, and when to publish.

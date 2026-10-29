# Bufo

Bufo watches one person's own computers for untrusted use. It plants decoys
that trip when someone uses them, and watches for those trips from a
different machine than the one the bait is on, so the alarm comes from a
machine the intruder doesn't hold. It is open source; what each install
plants is secret.

## Docs

- `README.md` is shipped behavior; update it in the change that changes
  behavior, including what was dropped.
- `ARCHITECTURE.md` holds the design and its decisions. Read it before
  changing decoys, detection, storage, or what a host can do, and record new
  decisions there.

## Rules

- **This repository is public.** Never commit a placement, a seed, key
  material, the owner's machine or network names, or anything about a real
  install. Describe how decoys imitate, never what one became. Deployment
  details belong to the host that uses Bufo (Froggy), not here.
- **No tells in the code.** Nothing in the code may make a decoy
  recognizable: no fixed names, pools, paths, ports, token shapes, or
  markers. Placements come from the machine's surroundings and the owner's
  private seed.
- **Standalone.** Bufo imports no host's code and calls no host's services.
  A host (Froggy first) links Bufo's contract and uses Bufo when present;
  Bufo works without one.
- **Agents get nothing.** No agent or MCP tool reads or changes Bufo, and no
  output shows a placement.
- Replace old behavior outright: no backward compatibility, migrations, or
  transition modes unless the owner asks.

## Git

Commit by path (`git commit -- <paths>`), never `-a` or `add -A`, on the
current branch. Commits are save points.

# runbook-anonymizer

Anonymize an Obsidian-style markdown bundle (BCM, Kubernetes, RunAI, ...)
before it leaves your laptop. Stdlib-only Python — no dependencies, no
network, no LLM. Read `anonymize.py` before running it; it's meant to be
read.

## Quickstart

```bash
# 1. point it at the bundle, see what it would do (no changes)
./anonymize.py --client "Acme Widgets" --scan ~/obsidian/bcm-bundle | nvim -

# 2. dry-run the full diff
./anonymize.py --client "Acme Widgets" --dry-run ~/obsidian/bcm-bundle | nvim -

# 3. write the anonymized bundle
./anonymize.py --client "Acme Widgets" --out ~/bcm-bundle-anon ~/obsidian/bcm-bundle
```

`--client` is repeatable. Prefer `--client-file names.txt` (one name per
line, `#` comments allowed) so real customer names never land in shell
history.

## The four passes

1. **Client names** — case-insensitive search-and-replace with a static
   stand-in (`--replacement`, default `Wayland Megacorp`). Compacted
   variants (`AcmeWidgets`) are derived automatically.
2. **Networks** — every distinct IPv4 /24 found is remapped to a sequential
   range: `10.10.11.0/24`, `10.10.12.0/24`, ... Host octets are preserved
   (`10.200.14.5` -> `10.10.11.5`) so address relationships stay readable.
   CIDR suffixes are kept. Loopback, link-local, multicast, `0.0.0.0` and
   netmasks are left alone. Tune with `--net-base` / `--net-start`.
3. **InfiniBand** — GUIDs (`0x...`, `de:ad:...`, `fe80::...` forms) become
   `<ib-guid-001>` etc.; `ibnet*` names become `fabric-net-001` etc. Bare
   `ib0`/`ib1` interface names are left as-is (generic Linux names, not
   identifying) and counted in the summary.
4. **Hostnames** — FQDNs with a host part auto-detected ->
   `node-001.example.internal`, `node-002.example.internal`, ... Bare
   customer domains (exactly two labels, e.g. `bhicorp.com`) collapse to
   the generic domain itself (`example.internal`). Bare short hostnames
   are caught via `--host-pattern` regexes (e.g.
   `--host-pattern 'bcm-[a-z0-9-]+'`) plus `ssh`/`scp`/`mosh`/`ping`
   targets and `user@host` contexts. Public domains (`github.com`, ...),
   `*.cluster.local`, and file extensions (`notes.md`) are allowlisted.

After anonymizing, the output is re-scanned for surviving client-name
matches — survivors print as `LEAK` lines on stderr with file and line
context. Always `--dry-run` first and read the LEAK lines (if any)
before `--out`.

Passes run in an order that avoids mangling: networks, IB, hostnames, then
client names (so an FQDN containing the client name is replaced whole).

## Warnings

- `anonymize-map.json` (written next to the output) maps every old value to
  its replacement — **it contains the real names. Never commit it.** It's
  in `.gitignore` for exactly this reason. Same goes for your client-file.
- Binary attachments (images, PDFs, zips) are skipped — scrub those by hand.
- `--scan` and `--dry-run` exist so you can verify before writing. Use them.
- Nothing is ever edited in place; the source bundle is only read.

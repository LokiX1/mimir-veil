# runbook-anonymizer

Anonymize an Obsidian-style markdown bundle (BCM, Kubernetes, RunAI, ...)
before it leaves your laptop. Stdlib-only Python — no dependencies, no
network, no LLM. Read `anonymize.py` before running it; it's meant to be
read.

## Quickstart

```bash
# 1. point it at the bundle, see what it would do (no changes)
./anonymize.py --client "Acme Widgets" --domains "acme.com, acmewidgets.internal" --scan ~/obsidian/bcm-bundle | nvim -

# 2. dry-run the full diff
./anonymize.py --client "Acme Widgets" --domains "acme.com, acmewidgets.internal" --dry-run ~/obsidian/bcm-bundle | nvim -

# 3. write the anonymized bundle
./anonymize.py --client "Acme Widgets" --domains "acme.com, acmewidgets.internal" --out ~/bcm-bundle-anon ~/obsidian/bcm-bundle
```

`--client` is repeatable and accepts comma-delimited lists
(`--client "Acme, Globex"`). Prefer `--client-file names.txt` (one name per
line, `#` comments allowed) so real customer names never land in shell
history — and it's the way to pass a name containing a literal comma.

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
4. **Hostnames** — explicit-list driven: only FQDNs under `--domains`
   (repeatable, comma-delimited, or `--domain-file`) are anonymized.
   FQDNs with a host part become `node-001.example.internal`,
   `node-002.example.internal`, ...; a listed bare domain itself
   (`bhicorp.com`) collapses to the generic domain (`example.internal`).
   Everything else — Kubernetes field paths (`spec.containers`), Helm
   values (`nfd.enabled`), `cluster.local` — is left alone by design.
   Bare short hostnames are still caught via `--host-pattern` regexes
   (e.g. `--host-pattern 'bcm-[a-z0-9-]+'`) plus `ssh`/`scp`/`mosh`/`ping`
   targets and `user@host` contexts.

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
- Filenames are anonymized with the same rules (a name is an identifier
  too); a would-be collision aborts the run loudly instead of
  overwriting, and the old -> new names land in `anonymize-map.json`.

#!/usr/bin/env python3
"""
anonymize.py -- anonymize an Obsidian-style markdown bundle before it leaves
your laptop. Stdlib only, no dependencies, no network, no LLM.

Four passes:

  1. Client / company names. --client "Acme Widgets" (repeatable) or
     --client-file names.txt (one per line -- keeps real names out of shell
     history). Case-insensitive search-and-replace with a static stand-in
     (--replacement, default "Wayland Megacorp"). Compacted variants
     ("AcmeWidgets") are derived automatically.
  2. Networks. Every distinct IPv4 /24 found is remapped to a sequential
     documentation range: 10.10.11.0/24, 10.10.12.0/24, ... (--net-base,
     --net-start). Host octets are preserved, so 10.200.14.5 -> 10.10.11.5
     and address relationships stay readable. CIDR suffixes are kept.
     Loopback, link-local, multicast and netmasks are left alone.
  3. InfiniBand. GUIDs (0x0011223344556677 and de:ad:be:ef:00:11:22:33
     forms, plus fe80:: GIDs) -> <ib-guid-001> etc.; ibnet* names ->
     fabric-net-001 etc. Bare ib0/ib1 interface names are left as-is
     (generic Linux names, not identifying) and reported.
  4. Hostnames. FQDNs with a host part auto-detected and mapped to
     node-001, node-002, ... under a generic domain (--domain, default
     example.internal). Bare customer domains (exactly two labels, e.g.
     bhicorp.com) collapse to the generic domain itself. Bare short
     hostnames are caught via --host-pattern regexes plus ssh/scp
     targets and user@host contexts. Public domains (github.com, ...),
     *.cluster.local, and file extensions (notes.md) are allowlisted.

  After anonymizing, the output is re-scanned for any surviving
  client-name matches -- survivors are reported as LEAK lines on stderr
  with file and line context, so nothing slips through silently.

Nothing is ever edited in place. Dry-run first, read the diff, then write:

    ./anonymize.py --client-file clients.txt --dry-run ~/obsidian/bcm-bundle | nvim -
    ./anonymize.py --client-file clients.txt --out ~/bcm-bundle-anon ~/obsidian/bcm-bundle

A mapping of old -> new values is written to anonymize-map.json next to the
output. THAT FILE CONTAINS THE REAL VALUES. Do not commit it. Ever.
"""

import argparse
import difflib
import json
import re
import sys
from pathlib import Path

# ---------------------------------------------------------------- constants

SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico",
                 ".pdf", ".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz",
                 ".rpm", ".deb", ".iso", ".img", ".qcow2", ".vmdk", ".pyc",
                 ".mp4", ".mp3", ".wav", ".ogg"}

FILE_EXTS = {"md", "markdown", "yml", "yaml", "json", "toml", "ini", "cfg",
             "conf", "log", "txt", "sh", "bash", "zsh", "py", "pl", "rb",
             "go", "rs", "js", "ts", "java", "c", "h", "cpp", "cc", "html",
             "htm", "css", "xml", "csv", "tsv", "png", "jpg", "jpeg", "gif",
             "svg", "webp", "pdf", "zip", "tar", "gz", "rpm", "deb", "iso",
             "service", "timer", "socket", "mount", "target", "key", "crt",
             "pem", "pub", "sql", "db", "sqlite", "env"}

# Public / vendor domains that are never treated as customer hostnames.
PUBLIC_DOMAINS = {
    "github.com", "raw.githubusercontent.com", "gist.github.com",
    "gitlab.com", "bitbucket.org", "docker.io", "hub.docker.com",
    "quay.io", "ghcr.io", "kubernetes.io", "k8s.io", "helm.sh",
    "redhat.com", "access.redhat.com", "ubuntu.com", "debian.org",
    "archlinux.org", "nvidia.com", "mellanox.com", "kernel.org",
    "python.org", "pypi.org", "golang.org", "rust-lang.org", "nodejs.org",
    "microsoft.com", "google.com", "cloud.google.com", "aws.amazon.com",
    "azure.microsoft.com", "oracle.com", "intel.com", "amd.com",
    "supermicro.com", "dell.com", "hpe.com", "lenovo.com", "slack.com",
    "zoom.us", "wikipedia.org", "stackoverflow.com", "serverfault.com",
}

IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
FQDN_RE = re.compile(
    r"\b(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}\b")
GUID_HEX_RE = re.compile(r"\b0[xX][0-9a-fA-F]{12,16}\b")
GUID_COLON_RE = re.compile(r"\b(?:[0-9a-fA-F]{2}:){7}[0-9a-fA-F]{2}\b")
GID_RE = re.compile(r"\bfe80::[0-9a-fA-F:]+\b|\b(?:[0-9a-fA-F]{1,4}:){3,}[0-9a-fA-F:]*\b",
                      re.IGNORECASE)
IBNET_RE = re.compile(r"\bibnet[a-z0-9_-]*\b", re.IGNORECASE)
IB_IFACE_RE = re.compile(r"\bib\d+\b")
SSH_RE = re.compile(
    r"(?:^|[\s;>])(?:ssh|scp|mosh|ping)\s+"
    r"(?:-[A-Za-z0-9]+\s+)*"
    r"(?:([A-Za-z0-9_.\-]+)@)?"
    r"([A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)")
USER_AT_RE = re.compile(
    r"([A-Za-z0-9_.\-]+)@([A-Za-z0-9](?:[A-Za-z0-9.\-]*[A-Za-z0-9])?)")


# ---------------------------------------------------------------- helpers

def valid_ip(tok):
    try:
        return all(0 <= int(p) <= 255 for p in tok.split("."))
    except ValueError:
        return False


def skip_ip(ip):
    """Addresses that are not identifying: leave them alone."""
    if ip in ("0.0.0.0", "255.255.255.255"):
        return True
    a = int(ip.split(".")[0])
    if a == 127 or a >= 224:      # loopback, multicast/reserved, netmasks
        return True
    if ip.startswith("169.254."):  # link-local
        return True
    return False


def fqdn_ok(tok):
    labels = tok.split(".")
    if labels[-1].lower() in FILE_EXTS:
        return False
    dom2 = ".".join(labels[-2:]).lower()
    if dom2 in PUBLIC_DOMAINS:
        return False
    low = tok.lower()
    if low.endswith(".cluster.local") or low.endswith(".svc"):
        return False
    if all(re.fullmatch(r"\d+", l) for l in labels):
        return False
    return True


def iter_text_files(inputs):
    for inp in inputs:
        p = Path(inp)
        if p.is_file():
            yield p, p.name
        elif p.is_dir():
            for f in sorted(p.rglob("*")):
                if f.is_file() and f.suffix.lower() not in SKIP_SUFFIXES:
                    yield f, str(f.relative_to(p))
        else:
            print(f"SKIP {inp}: not found", file=sys.stderr)


def read_text(path):
    try:
        return path.read_text()
    except (UnicodeDecodeError, OSError):
        return None


# ---------------------------------------------------------------- pass 2: networks

def collect_networks(texts):
    nets = {}
    for text in texts:
        for m in IP_RE.finditer(text):
            ip = m.group(0)
            if valid_ip(ip) and not skip_ip(ip):
                nets.setdefault(".".join(ip.split(".")[:3]), set()).add(ip)
    return nets


def assign_networks(nets, base, start):
    observed = {f"{n}.0/24" for n in nets}
    mapping, i = {}, start
    for net in sorted(nets):
        while f"{base}.{i}.0/24" in observed:
            i += 1
        mapping[net] = f"{base}.{i}"
        i += 1
    return mapping


def find_client_leaks(text, client_pats, replacement):
    """Client-name matches surviving in anonymized text.

    The replacement stand-in is masked first (same length, so offsets stay
    aligned) so a client pattern that is a substring of the stand-in itself
    -- e.g. "Mega" inside "Wayland Megacorp" -- doesn't false-positive.
    Returns a list of (pattern, line) with the line shown as anonymized.
    """
    if not client_pats:
        return []
    mask = "\x00" * len(replacement)
    masked = text.replace(replacement, mask)
    leaks = []
    for c in client_pats:
        for m in re.finditer(re.escape(c), masked, re.IGNORECASE):
            s = masked.rfind("\n", 0, m.start()) + 1
            e = masked.find("\n", m.end())
            line = text[s:e if e != -1 else len(text)].strip()
            leaks.append((c, line.replace(mask, replacement)))
    return leaks


# ---------------------------------------------------------------- pass 4: hostnames

def collect_hostnames(texts, extra_patterns):
    fqdns, bare = set(), set()
    for text in texts:
        for m in FQDN_RE.finditer(text):
            tok = m.group(0)
            if fqdn_ok(tok):
                fqdns.add(tok)
        for m in SSH_RE.finditer(text):
            host = m.group(2)
            if valid_ip(host):
                continue
            if "." in host:
                if fqdn_ok(host):
                    fqdns.add(host)
            elif re.search(r"[A-Za-z]", host) and len(host) > 1:
                bare.add(host)
        for m in USER_AT_RE.finditer(text):
            host = m.group(2)
            if valid_ip(host) or len(host) < 2:
                continue
            if "." in host:
                if fqdn_ok(host):
                    fqdns.add(host)
            elif re.search(r"[A-Za-z]", host):
                bare.add(host)
        for pat in extra_patterns:
            for m in pat.finditer(text):
                tok = m.group(0)
                if not valid_ip(tok) and re.search(r"[A-Za-z]", tok):
                    bare.add(tok)
    return fqdns, bare


def assign_hostnames(fqdns, bare, prefix, domain):
    mapping = {}
    n = 0
    # Bare customer domains (exactly two labels, e.g. bhicorp.com) are not
    # nodes -- they collapse to the generic domain itself. Only FQDNs with a
    # host part (three or more labels) become node-NNN. Distinct bare domains
    # that collide on the generic domain are visible in --scan output.
    hosts = []
    for fq in sorted(fqdns, key=str.lower):
        if len(fq.split(".")) == 2:
            mapping[fq] = domain
        else:
            hosts.append(fq)
    for fq in hosts:
        n += 1
        mapping[fq] = f"{prefix}-{n:03d}.{domain}"
    # A bare occurrence of an FQDN's first label (e.g. `ssh bcm-head01`
    # when `bcm-head01.acmewidgets.internal` exists) maps to the same node
    # short name, so it doesn't leak. Ambiguous labels (same first label
    # on multiple domains) keep their own node-NNN entry.
    label_to_nodes = {}
    for fq, node in mapping.items():
        label_to_nodes.setdefault(fq.split(".")[0].lower(), set()).add(node)
    for b in sorted(bare, key=str.lower):
        n += 1
        nodes = label_to_nodes.get(b.lower(), set())
        if len(nodes) == 1:
            mapping[b] = next(iter(nodes)).split(".")[0]
        else:
            mapping[b] = f"{prefix}-{n:03d}"
    return mapping


# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(
        description="Anonymize an Obsidian markdown bundle (4 passes).")
    ap.add_argument("inputs", nargs="+", help="files or directories to process")
    ap.add_argument("--client", action="append", default=[],
                    help="client/company name to replace (repeatable)")
    ap.add_argument("--client-file",
                    help="file with one client name per line (avoids shell history)")
    ap.add_argument("--replacement", default="Wayland Megacorp",
                    help="static stand-in for client names")
    ap.add_argument("--net-base", default="10.10",
                    help="first two octets of anonymized ranges")
    ap.add_argument("--net-start", type=int, default=11,
                    help="third octet to start anonymized ranges at")
    ap.add_argument("--host-pattern", action="append", default=[],
                    help="extra regex for bare hostnames, e.g. 'bcm-[a-z0-9-]+' (repeatable)")
    ap.add_argument("--host-prefix", default="node",
                    help="generic hostname stem")
    ap.add_argument("--domain", default="example.internal",
                    help="generic domain for anonymized FQDNs")
    ap.add_argument("--out", "-o", help="output directory")
    ap.add_argument("--map", help="mapping file path (default: <out>/anonymize-map.json)")
    ap.add_argument("--dry-run", action="store_true",
                    help="print unified diffs, write nothing")
    ap.add_argument("--scan", action="store_true",
                    help="report what would be anonymized, change nothing")
    args = ap.parse_args()

    # ---- gather inputs
    files = [(p, rel) for p, rel in iter_text_files(args.inputs)]
    texts = {}
    for p, rel in files:
        t = read_text(p)
        if t is None:
            print(f"SKIP {rel}: not decodable text", file=sys.stderr)
        else:
            texts[rel] = t
    if not texts:
        print("No text files found.", file=sys.stderr)
        return 1

    # ---- client names
    clients = list(args.client)
    if args.client_file:
        clients += [l.strip() for l in Path(args.client_file).read_text().splitlines()
                    if l.strip() and not l.startswith("#")]
    client_pats = set()
    for name in clients:
        client_pats.add(name)
        compact = re.sub(r"[^A-Za-z0-9]", "", name)
        if compact and compact.lower() != name.lower():
            client_pats.add(compact)
    client_pats = sorted(client_pats, key=len, reverse=True)

    # ---- pass 2: networks (detect first, on raw text)
    nets = collect_networks(texts.values())
    netmap = assign_networks(nets, args.net_base, args.net_start)

    # ---- pass 3: IB
    guids, ibnets = set(), set()
    for t in texts.values():
        guids.update(GUID_HEX_RE.findall(t))
        guids.update(m for m in GUID_COLON_RE.findall(t))
        guids.update(m for m in GID_RE.findall(t)
                     if not GUID_COLON_RE.fullmatch(m))
        ibnets.update(m.lower() for m in IBNET_RE.findall(t))
    guidmap = {g: f"<ib-guid-{i:03d}>"
               for i, g in enumerate(sorted(guids, key=str.lower), 1)}
    ibnetmap = {n: f"fabric-net-{i:03d}"
                for i, n in enumerate(sorted(ibnets), 1)}
    ib_ifaces = sum(len(IB_IFACE_RE.findall(t)) for t in texts.values())

    # ---- pass 4: hostnames (detect on raw text, before client replacement)
    extra = [re.compile(p) for p in args.host_pattern]
    fqdns, bare = collect_hostnames(texts.values(), extra)
    hostmap = assign_hostnames(fqdns, bare, args.host_prefix, args.domain)

    if args.scan:
        print("== client names ==")
        for c in client_pats:
            n = sum(t.lower().count(c.lower()) for t in texts.values())
            print(f"  {n:5d}  {c}")
        print("== networks ==")
        for old, new in sorted(netmap.items()):
            print(f"  {old}.0/24 -> {new}.0/24 ({len(nets[old])} addrs)")
        print("== infiniband ==")
        for g, r in sorted(guidmap.items(), key=lambda kv: kv[1]):
            print(f"  {r}  <- {g}")
        for n_, r in sorted(ibnetmap.items(), key=lambda kv: kv[1]):
            print(f"  {r}  <- {n_}")
        print(f"  ibN interface refs left as-is: {ib_ifaces}")
        print("== hostnames ==")
        for old, new in sorted(hostmap.items(), key=lambda kv: kv[1]):
            print(f"  {new}  <- {old}")
        return 0

    # ---- build ordered replacement list: hostnames, IB, networks, clients
    # (hostnames before client names so FQDNs containing the client name
    # are replaced whole instead of being mangled mid-domain)
    repls = []
    for old in sorted(hostmap, key=len, reverse=True):
        repls.append((re.compile(r"\b" + re.escape(old) + r"\b"), hostmap[old]))
    for old in sorted(ibnetmap, key=len, reverse=True):
        repls.append((re.compile(re.escape(old), re.IGNORECASE), ibnetmap[old]))
    for old in sorted(guidmap, key=len, reverse=True):
        repls.append((re.compile(re.escape(old)), guidmap[old]))

    def net_repl(m):
        ip = m.group(0)
        if not valid_ip(ip) or skip_ip(ip):
            return ip
        new = netmap.get(".".join(ip.split(".")[:3]))
        return f"{new}.{ip.split('.')[3]}" if new else ip
    repls.append((IP_RE, net_repl))

    for c in client_pats:
        repls.append((re.compile(re.escape(c), re.IGNORECASE), args.replacement))

    def anonymize(text):
        for rx, rep in repls:
            text = rx.sub(rep, text) if isinstance(rep, str) else rx.sub(rep, text)
        return text

    if not args.dry_run and not args.out:
        ap.error("need --out or --dry-run/--scan")

    outdir = Path(args.out) if args.out else None
    leak_total = 0
    for rel, text in texts.items():
        new = anonymize(text)
        for pat, line in find_client_leaks(new, client_pats, args.replacement):
            leak_total += 1
            print(f"LEAK {rel}: client pattern {pat!r} survives: "
                  f"{line[:200]}", file=sys.stderr)
        if args.dry_run:
            if new != text:
                print("\n".join(difflib.unified_diff(
                    text.splitlines(), new.splitlines(),
                    fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="")))
        else:
            dest = outdir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(new)

    # ---- mapping file (PRIVATE -- contains real values)
    mappath = Path(args.map) if args.map else (
        (outdir / "anonymize-map.json") if outdir else Path("anonymize-map.json"))
    if not args.dry_run:
        mappath.write_text(json.dumps({
            "client_names": {c: args.replacement for c in client_pats},
            "networks": {f"{k}.0/24": f"{v}.0/24" for k, v in sorted(netmap.items())},
            "hostnames": dict(sorted(hostmap.items(), key=lambda kv: kv[1])),
            "ib_guids": dict(sorted(guidmap.items(), key=lambda kv: kv[1])),
            "ib_nets": dict(sorted(ibnetmap.items(), key=lambda kv: kv[1])),
        }, indent=2))
        print(f"\nWROTE {mappath} -- PRIVATE, contains real values. "
              f"Do not commit.", file=sys.stderr)

    print(f"\nSummary: {len(client_pats)} client patterns, "
          f"{len(netmap)} networks, {len(hostmap)} hostnames "
          f"({len(fqdns)} FQDN, {len(bare)} bare), "
          f"{len(guidmap)} IB GUIDs, {len(ibnetmap)} ibnet names, "
          f"{ib_ifaces} ibN refs left as-is, "
          f"{leak_total} client-name leaks surviving.",
          file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())

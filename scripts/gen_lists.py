#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.11"
# dependencies = []
# ///
"""Generate the embedded word lists in internal/detect/data/.

Downloads (in memory) the public-domain sources listed in SOURCES and writes
one sorted, LF-terminated, UTF-8 file per list. Everything is validated
before anything is written; any failure exits non-zero and leaves the data
directory untouched.

A second run must change nothing: files are rewritten only when their
content differs, and a SOURCES line keeps its old date unless its file
changed.

--ssa/--census take local copies of the two zips (the SSA and Census hosts
block scripts); SOURCES still records the canonical URL, marked "(local
copy)". --only limits the run to some lists and leaves the other files and
SOURCES lines alone.
"""

import argparse
import csv
import datetime
import html.parser
import io
import re
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "internal" / "detect" / "data"

URL_TLDS = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
URL_SSA = "https://www.ssa.gov/oact/babynames/names.zip"
URL_CENSUS = "https://www2.census.gov/topics/genealogy/2010surnames/names.zip"
URL_WEB2 = "https://raw.githubusercontent.com/freebsd/freebsd-src/main/share/dict/web2"
URL_USPS = "https://pe.usps.com/text/pub28/28apc_002.htm"

FIRST_YEAR = 1940
KEEP = 20000
TIER3_MAX = 1000  # rank <= 1000 is tier 3
TIER2_MAX = 5000  # rank <= 5000 is tier 2, the rest tier 1

MIN_TLDS = 1000
MIN_SUFFIXES = 300
MIN_NAME_WORDS = 1000

# Some of these hosts reject urllib's default User-Agent.
HEADERS = {
    "User-Agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36"
    ),
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
}


def fetch(url):
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:
            return resp.read()
    except OSError as e:
        sys.exit(f"cannot download {url}: {e}")


def tier(rank):
    if rank <= TIER3_MAX:
        return 3
    if rank <= TIER2_MAX:
        return 2
    return 1


def tlds():
    out = set()
    for line in fetch(URL_TLDS).decode("utf-8").splitlines():
        line = line.strip().lower()
        if line and not line.startswith("#"):
            out.add(line)
    return out


def first_names(data):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        sys.exit(f"{URL_SSA}: not a zip file (blocked?): {data[:80]!r}")
    totals = {}
    years = []
    for name in zf.namelist():
        m = re.fullmatch(r"yob(\d{4})\.txt", name)
        if m:
            years.append((int(m.group(1)), name))
    if not years:
        sys.exit(f"{URL_SSA}: no yobYYYY.txt files in the archive")
    latest = max(y for y, _ in years)
    used = 0
    for year, name in years:
        if year < FIRST_YEAR:
            continue
        used += 1
        for line in zf.read(name).decode("utf-8").splitlines():
            if not line.strip():
                continue
            nm, _sex, count = line.split(",")
            nm = nm.strip().lower()
            totals[nm] = totals.get(nm, 0) + int(count)
    if used != latest - FIRST_YEAR + 1:
        sys.exit(f"SSA archive is missing years between {FIRST_YEAR} and {latest}")
    ranked = sorted(totals, key=lambda n: (-totals[n], n))[:KEEP]
    return {n: tier(i + 1) for i, n in enumerate(ranked)}


def surnames(data):
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except zipfile.BadZipFile:
        sys.exit(f"{URL_CENSUS}: not a zip file (blocked?): {data[:80]!r}")
    if "Names_2010Census.csv" not in zf.namelist():
        sys.exit(f"{URL_CENSUS}: Names_2010Census.csv not in {zf.namelist()}")
    text = zf.read("Names_2010Census.csv").decode("utf-8-sig")
    rows = []
    for rec in csv.DictReader(io.StringIO(text)):
        nm = rec["name"].strip().lower()
        if nm == "all other names":
            continue
        rows.append((int(rec["rank"]), nm))
    rows.sort()
    kept = rows[:KEEP]
    return {nm: tier(i + 1) for i, (_rank, nm) in enumerate(kept)}


def name_words(names):
    out = set()
    for line in fetch(URL_WEB2).decode("utf-8", errors="replace").splitlines():
        w = line.strip()
        if w and w == w.lower() and w in names:
            out.add(w)
    return out


class SuffixTable(html.parser.HTMLParser):
    """Collect the rows of every table; the suffix table is the longest."""

    def __init__(self):
        super().__init__()
        self.tables = []
        self.stack = []
        self.row = None
        self.cell = None

    def handle_starttag(self, tag, attrs):
        if tag == "table":
            self.stack.append([])
        elif tag == "tr" and self.stack:
            self.row = []
        elif tag in ("td", "th") and self.row is not None:
            self.cell = ""

    def handle_endtag(self, tag):
        if tag in ("td", "th") and self.cell is not None and self.row is not None:
            self.row.append(self.cell)
            self.cell = None
        elif tag == "tr" and self.row is not None and self.stack:
            self.stack[-1].append(self.row)
            self.row = None
        elif tag == "table" and self.stack:
            self.tables.append(self.stack.pop())

    def handle_data(self, data):
        if self.cell is not None:
            self.cell += data


def street_suffixes():
    parser = SuffixTable()
    parser.feed(fetch(URL_USPS).decode("utf-8", errors="replace"))
    if not parser.tables:
        sys.exit(f"{URL_USPS}: no tables found")
    rows = max(parser.tables, key=len)
    header = " ".join(rows[0]).lower().replace(" ", "")
    if "primary" not in header or "abbreviation" not in header:
        sys.exit(f"{URL_USPS}: unexpected table header {rows[0]!r}")
    out = set()
    for row in rows[1:]:
        for cell in row:
            for tok in cell.lower().split():
                tok = tok.strip()
                if tok:
                    out.add(tok)
    return out


def render_list(items):
    return "".join(f"{i}\n" for i in sorted(items))


def render_tiered(d):
    return "".join(f"{n}\t{d[n]}\n" for n in sorted(d))


GROUPS = {
    "tlds": ("tlds.txt",),
    "suffixes": ("street_suffixes.txt",),
    "names": ("first_names.txt", "surnames.txt", "name_words.txt"),
}


def parse_sources(text):
    """Map file name to its raw SOURCES line (without the newline)."""
    out = {}
    for line in text.splitlines():
        m = re.fullmatch(r"(\S+): (\S+) \(retrieved \d{4}-\d{2}-\d{2}\)( \(local copy\))?", line)
        if m:
            out[m.group(1)] = line
    return out


def require(cond, msg):
    if not cond:
        sys.exit(f"validation failed: {msg}")


def read_local(path):
    try:
        return Path(path).read_bytes()
    except OSError as e:
        sys.exit(f"cannot read {path}: {e}")


def check_entries(label, items):
    for i in items:
        require(i and i == i.strip() and "\t" not in i and "\n" not in i, f"bad {label} entry {i!r}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--ssa", metavar="PATH", help="local SSA names.zip instead of the download")
    ap.add_argument("--census", metavar="PATH", help="local Census names.zip instead of the download")
    ap.add_argument("--only", metavar="LIST", help="comma-separated subset of " + ",".join(GROUPS))
    args = ap.parse_args()

    only = list(GROUPS) if args.only is None else [g.strip() for g in args.only.split(",") if g.strip()]
    for g in only:
        if g not in GROUPS:
            sys.exit(f"--only: unknown list {g!r}, want a subset of {','.join(GROUPS)}")
    if not only:
        sys.exit("--only: empty list")

    # name: (content, url, local copy?)
    files = {}
    if "tlds" in only:
        t = tlds()
        require(len(t) >= MIN_TLDS, f"{len(t)} TLDs, want >= {MIN_TLDS}")
        require("com" in t and "io" in t, "TLDs miss com/io")
        check_entries("tld", t)
        files["tlds.txt"] = (render_list(t), URL_TLDS, False)
    if "suffixes" in only:
        suf = street_suffixes()
        require(len(suf) >= MIN_SUFFIXES, f"{len(suf)} street suffixes, want >= {MIN_SUFFIXES}")
        require({"st", "avenue", "blvd"} <= suf, "street suffixes miss st/avenue/blvd")
        check_entries("suffix", suf)
        files["street_suffixes.txt"] = (render_list(suf), URL_USPS, False)
    if "names" in only:
        first = first_names(read_local(args.ssa) if args.ssa else fetch(URL_SSA))
        sur = surnames(read_local(args.census) if args.census else fetch(URL_CENSUS))
        words = name_words(set(first) | set(sur))
        require(len(first) == KEEP, f"{len(first)} first names, want {KEEP}")
        require(len(sur) == KEEP, f"{len(sur)} surnames, want {KEEP}")
        require(len(words) >= MIN_NAME_WORDS, f"{len(words)} name words, want >= {MIN_NAME_WORDS}")
        require(first.get("jennifer") == 3, "jennifer is not a tier 3 first name")
        require(sur.get("smith") == 3, "smith is not a tier 3 surname")
        check_entries("first name", first)
        check_entries("surname", sur)
        check_entries("name word", words)
        files["first_names.txt"] = (render_tiered(first), URL_SSA, bool(args.ssa))
        files["surnames.txt"] = (render_tiered(sur), URL_CENSUS, bool(args.census))
        files["name_words.txt"] = (render_list(words), URL_WEB2, False)

    OUT.mkdir(parents=True, exist_ok=True)
    sources_path = OUT / "SOURCES"
    sources = {}
    if sources_path.exists():
        sources = parse_sources(sources_path.read_text(encoding="utf-8"))

    today = datetime.datetime.now(datetime.timezone.utc).date().isoformat()
    for name, (content, url, local) in files.items():
        path = OUT / name
        data = content.encode("utf-8")
        old = path.read_bytes() if path.exists() else None
        suffix = " (local copy)" if local else ""
        line = f"{name}: {url} (retrieved {today}){suffix}"
        if old == data and name in sources:
            kept = sources[name]
            if kept.startswith(f"{name}: {url} (retrieved ") and kept.endswith(suffix) == bool(suffix):
                line = kept
        if old != data:
            path.write_bytes(data)
        sources[name] = line
        print(f"{name}: {content.count(chr(10))} entries", file=sys.stderr)

    text = "".join(f"{sources[n]}\n" for n in sorted(sources))
    if not sources_path.exists() or sources_path.read_text(encoding="utf-8") != text:
        sources_path.write_text(text, encoding="utf-8")


main()

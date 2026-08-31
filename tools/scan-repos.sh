#!/usr/bin/env bash
#
# scan-repos.sh — run the hoeg/k8s-operators pack over a list of GitHub repositories.
#
# Downloads GitHub's prebuilt CodeQL database for each repo, analyses it, records the
# results, and deletes the database before moving on. Falls back to building a database
# locally when none is published.
#
#   ./tools/scan-repos.sh repos.txt
#   ./tools/scan-repos.sh repos.txt -j 6 -o ./scan-out
#   ./tools/scan-repos.sh repos.txt --mode build      # force local builds
#
# INPUT   One repo per line as owner/name. Blank lines and lines starting with '#' are
#         skipped. Anything after the first whitespace/tab is ignored, so a richer
#         manifest (priority, size, flags) can be fed in unchanged.
#
# OUTPUT  <outdir>/results.jsonl   one JSON object per repo, appended as each finishes
#         <outdir>/sarif/<slug>.sarif
#         <outdir>/findings.tsv    one row per finding: repo, rule, source, sink
#         <outdir>/summary.md      written at the end
#         <outdir>/logs/<slug>.log
#
# READ THIS BEFORE TRUSTING A ZERO
#   A repo where no custom-resource type resolves is *blind*, not clean: both queries
#   lose their sinks and report nothing. The pack ships a diagnostic for exactly this,
#   and this script surfaces it as status=blind. Never fold those into "no findings".
#
# Requires: codeql (2.20+), gh (authenticated), python3. go + git only for --mode build.

set -uo pipefail

if [[ -z "${BASH_VERSINFO:-}" || "${BASH_VERSINFO[0]}" -lt 4 ]]; then
  echo "error: bash 4+ required (found ${BASH_VERSION:-unknown})." >&2
  echo "       macOS ships bash 3.2 at /bin/bash; install a newer one (brew install bash)" >&2
  echo "       and run via that, e.g.: /opt/homebrew/bin/bash tools/scan-repos.sh ..." >&2
  exit 2
fi

# ---------------------------------------------------------------- defaults

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PACK_DIR="$REPO_ROOT/src"
SUITE="$PACK_DIR/codeql-suites/k8s-operators.qls"

OUTDIR="./scan-out"
JOBS=4
MODE="auto"              # auto | download | build
TIMEOUT_SECS=900         # per-repo analysis cap
MIN_DISK_GB=6            # halt a worker below this
RAM_MB=4000
KEEP_DB=0
RESUME=1

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  cat <<EOF

Options
  -o, --out DIR        output directory (default: $OUTDIR)
  -j, --jobs N         repos analysed concurrently (default: $JOBS)
      --mode MODE      auto | download | build (default: $MODE)
                       auto     try the prebuilt database, build if absent
                       download prebuilt only; skip repos without one
                       build    always build locally (slow; needs a working Go toolchain)
      --timeout SECS   per-repo analysis timeout (default: $TIMEOUT_SECS)
      --ram MB         codeql --ram per analysis (default: $RAM_MB)
      --min-disk GB    stop a worker when free space drops below this (default: $MIN_DISK_GB)
      --keep-db        do not delete databases after analysis (needs a lot of disk)
      --no-resume      re-scan repos already present in results.jsonl
  -h, --help           this text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -o|--out)       OUTDIR="$2"; shift 2 ;;
    -j|--jobs)      JOBS="$2"; shift 2 ;;
    --mode)         MODE="$2"; shift 2 ;;
    --timeout)      TIMEOUT_SECS="$2"; shift 2 ;;
    --ram)          RAM_MB="$2"; shift 2 ;;
    --min-disk)     MIN_DISK_GB="$2"; shift 2 ;;
    --keep-db)      KEEP_DB=1; shift ;;
    --no-resume)    RESUME=0; shift ;;
    -h|--help)      usage; exit 0 ;;
    -*)             echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
    *)              REPO_LIST="${REPO_LIST:-$1}"; shift ;;
  esac
done

if [[ -z "${REPO_LIST:-}" ]]; then
  echo "error: no repo list given" >&2; usage >&2; exit 2
fi
[[ -r "$REPO_LIST" ]] || { echo "error: cannot read $REPO_LIST" >&2; exit 2; }

case "$MODE" in auto|download|build) ;; *) echo "error: --mode must be auto|download|build" >&2; exit 2 ;; esac

# ---------------------------------------------------------------- preflight

need() { command -v "$1" >/dev/null 2>&1 || { echo "error: '$1' not found on PATH" >&2; exit 2; }; }
need codeql
need python3
[[ "$MODE" == "build" ]] || need gh

if [[ "$MODE" != "build" ]] && ! gh auth status >/dev/null 2>&1; then
  echo "error: gh is not authenticated (run: gh auth login)" >&2; exit 2
fi

[[ -f "$PACK_DIR/qlpack.yml" ]] || { echo "error: pack not found at $PACK_DIR" >&2; exit 2; }

# The pack needs its lock file resolved or every analysis fails identically.
if ! codeql pack install --mode verify "$PACK_DIR" >/dev/null 2>&1; then
  echo "note: resolving pack dependencies..." >&2
  codeql pack install "$PACK_DIR" >/dev/null || { echo "error: codeql pack install failed" >&2; exit 2; }
fi

mkdir -p "$OUTDIR"/{sarif,logs,work}
RESULTS="$OUTDIR/results.jsonl"
FINDINGS="$OUTDIR/findings.tsv"
touch "$RESULTS"
[[ -s "$FINDINGS" ]] || printf 'repo\trule\tsource\tsink\tmessage\n' > "$FINDINGS"

LOCK="$OUTDIR/.write.lock"

# Serialise appends so concurrent workers cannot interleave a line.
emit() {  # emit <file> <line>
  local f="$1"; shift
  # mkdir is atomic everywhere; flock is Linux-only and absent on macOS.
  local n=0
  until mkdir "$LOCK" 2>/dev/null; do
    n=$((n+1)); [[ $n -gt 2000 ]] && { rm -rf "$LOCK"; n=0; }
    sleep 0.01
  done
  printf '%s\n' "$*" >> "$f"
  rmdir "$LOCK" 2>/dev/null || true
}

free_gb() { df -Pk "$OUTDIR" | awk 'NR==2 {print int($4/1048576)}'; }

# `timeout` is GNU; macOS ships it only via coreutils. Fall back to a background+kill.
run_limited() {  # run_limited <secs> <cmd...>
  local secs="$1"; shift
  if command -v timeout >/dev/null 2>&1; then
    timeout --preserve-status "$secs" "$@"
  elif command -v gtimeout >/dev/null 2>&1; then
    gtimeout --preserve-status "$secs" "$@"
  else
    "$@" & local pid=$!
    ( sleep "$secs"; kill -TERM "$pid" 2>/dev/null ) & local watcher=$!
    wait "$pid"; local rc=$?
    kill -TERM "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
    return $rc
  fi
}

# ---------------------------------------------------------------- SARIF parsing
#
# Two things this has to get right, both learned the hard way:
#  * Diagnostic-kind queries do NOT appear in runs[].results. They land in
#    runs[].invocations[].toolExecutionNotifications. Anyone reading CSV concludes the
#    diagnostic never fires.
#  * A CSV export deduplicates alerts that share a sink, which silently hides distinct
#    source->sink pairs. Parse the SARIF.

read -r -d '' PARSE_PY <<'PYEOF'
import json, sys, os

sarif_path, repo = sys.argv[1], sys.argv[2]
try:
    with open(sarif_path) as fh:
        doc = json.load(fh)
except Exception as exc:
    print(json.dumps({"repo": repo, "status": "parse-error", "error": str(exc)[:200],
                      "findings": 0, "blind": False, "rows": []}))
    sys.exit(0)

def loc_of(phys):
    # Column is load-bearing, not decoration: two CR fields read on the same line are
    # two distinct sources, and dropping the column silently merges them into one.
    art = (phys.get("artifactLocation") or {}).get("uri", "?")
    reg = phys.get("region") or {}
    line, col = reg.get("startLine", "?"), reg.get("startColumn")
    return f"{art}:{line}:{col}" if col is not None else f"{art}:{line}"

rows, blind, diag_msgs = [], False, []

for run in doc.get("runs", []):
    for inv in run.get("invocations", []):
        for note in inv.get("toolExecutionNotifications", []):
            rule = ((note.get("associatedRule") or {}).get("id")
                    or (note.get("descriptor") or {}).get("id") or "")
            text = ((note.get("message") or {}).get("text") or "").strip()
            if note.get("level") in ("error", "warning") and "custom-resource" in (rule + text).lower():
                blind = True
                diag_msgs.append(text[:400])

    for res in run.get("results", []):
        rule = res.get("ruleId") or ""
        msg = ((res.get("message") or {}).get("text") or "").strip()
        locs = res.get("locations") or []
        sink = loc_of(locs[0].get("physicalLocation") or {}) if locs else "?"

        # SARIF MERGES every alert sharing a (rule, sink) into ONE result carrying
        # several codeFlows. Counting results therefore under-reports: three distinct
        # sources leaking into one status field appear as a single finding. Emit one
        # row per code flow instead, deduplicated on (source, sink) because a single
        # source can reach a sink by more than one path.
        flows = res.get("codeFlows") or []
        sources = []
        for flow in flows:
            for tflow in flow.get("threadFlows") or []:
                tl = tflow.get("locations") or []
                if tl:
                    sources.append(loc_of((tl[0].get("location") or {}).get("physicalLocation") or {}))
                    break
        if not sources:
            sources = [sink]          # a path-less alert, e.g. @kind problem

        for source in dict.fromkeys(sources):
            rows.append({"rule": rule, "source": source, "sink": sink, "message": msg})

print(json.dumps({"repo": repo, "status": "ok", "findings": len(rows),
                  "blind": blind, "diagnostic": diag_msgs[:2], "rows": rows}))
PYEOF

# ---------------------------------------------------------------- per-repo work

scan_one() {  # scan_one <worker-id> <owner/repo>
  local wid="$1" repo="$2"
  local slug="${repo//\//_}"
  local log="$OUTDIR/logs/$slug.log"
  # Worker id AND slug in every path: two workers sharing a scratch path silently
  # clobber each other and one shard's worth of repos vanishes.
  local work="$OUTDIR/work/w${wid}-${slug}"
  local db="$work/db" zip="$work/db.zip" src="$work/src"
  local sarif="$OUTDIR/sarif/$slug.sarif"
  local started; started="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

  mkdir -p "$work"
  : > "$log"

  if [[ "$(free_gb)" -lt "$MIN_DISK_GB" ]]; then
    emit "$RESULTS" "$(python3 -c 'import json,sys; print(json.dumps({"repo":sys.argv[1],"status":"skipped-disk","findings":0,"blind":False}))' "$repo")"
    echo "  [$repo] SKIPPED — free disk under ${MIN_DISK_GB}G" >&2
    rm -rf "$work"; return 0
  fi

  local acquired=""

  # ---- 1. prebuilt database
  if [[ "$MODE" == "auto" || "$MODE" == "download" ]]; then
    echo "== fetching prebuilt database" >> "$log"
    if gh api "/repos/$repo/code-scanning/codeql/databases/go" \
         -H "Accept: application/zip" > "$zip" 2>>"$log" && [[ -s "$zip" ]]; then
      if codeql database unbundle "$zip" --target="$work" --name=db >>"$log" 2>&1; then
        acquired="download"
      else
        echo "unbundle failed" >> "$log"
      fi
    else
      echo "no prebuilt go database (code scanning off, or none published)" >> "$log"
    fi
    rm -f "$zip"
  fi

  # ---- 2. local build fallback
  if [[ -z "$acquired" && ( "$MODE" == "auto" || "$MODE" == "build" ) ]]; then
    echo "== building database locally" >> "$log"
    if git clone --depth=1 "https://github.com/$repo" "$src" >>"$log" 2>&1; then
      # GOTOOLCHAIN=auto matters: most operators declare a newer Go than is installed
      # and will not build without it.
      ( cd "$src" && GOTOOLCHAIN=auto go mod download all ) >>"$log" 2>&1
      if GOTOOLCHAIN=auto codeql database create "$db" --language=go \
           --source-root="$src" --overwrite --ram="$RAM_MB" >>"$log" 2>&1; then
        acquired="build"
      else
        # `codeql database create` needs the build tracer, which on Apple Silicon
        # requires Rosetta 2 (preload_tracer runs children through the x86_64 slice).
        # The Go extractor itself does not need tracing, so drive it directly.
        echo "== tracer failed; retrying untraced" >> "$log"
        rm -rf "$db"
        if codeql database init "$db" --language=go --source-root="$src" \
             --build-mode=manual >>"$log" 2>&1; then
          local dist ext
          dist="$(codeql version --format=json | python3 -c 'import json,sys; print(json.load(sys.stdin)["unpackedLocation"])')"
          ext="$dist/go/tools/$(uname -s | tr 'A-Z' 'a-z')64/go-autobuilder"
          [[ -x "$ext" ]] || ext="$(find "$dist/go/tools" -name 'go-autobuilder' -perm -u+x 2>/dev/null | head -1)"
          if [[ -x "$ext" ]]; then
            ( cd "$src" \
              && CODEQL_EXTRACTOR_GO_ROOT="$dist/go" \
                 CODEQL_EXTRACTOR_GO_TRAP_DIR="$db/trap/go" \
                 CODEQL_EXTRACTOR_GO_SOURCE_ARCHIVE_DIR="$db/src" \
                 CODEQL_EXTRACTOR_GO_WIP_DATABASE="$db" \
                 GOTOOLCHAIN=auto "$ext" ) >>"$log" 2>&1
            codeql database finalize "$db" >>"$log" 2>&1 && acquired="build-untraced"
          fi
        fi
      fi
    fi
    rm -rf "$src"
  fi

  if [[ -z "$acquired" ]]; then
    emit "$RESULTS" "$(python3 -c 'import json,sys; print(json.dumps({"repo":sys.argv[1],"status":"no-database","findings":0,"blind":False}))' "$repo")"
    echo "  [$repo] no database" >&2
    rm -rf "$work"; return 0
  fi

  # ---- 3. analyse
  echo "== analysing ($acquired)" >> "$log"
  local rc=0
  run_limited "$TIMEOUT_SECS" codeql database analyze "$db" "$SUITE" \
      --format=sarif-latest --output="$sarif" \
      --ram="$RAM_MB" --threads=2 --rerun --search-path="$REPO_ROOT" >>"$log" 2>&1 || rc=$?

  if [[ $rc -ne 0 || ! -s "$sarif" ]]; then
    local st="analyze-failed"; [[ $rc -eq 124 || $rc -eq 143 ]] && st="timeout"
    emit "$RESULTS" "$(python3 -c 'import json,sys; print(json.dumps({"repo":sys.argv[1],"status":sys.argv[2],"findings":0,"blind":False}))' "$repo" "$st")"
    echo "  [$repo] $st (see $log)" >&2
    [[ $KEEP_DB -eq 1 ]] || rm -rf "$work"
    return 0
  fi

  # ---- 4. record
  local parsed; parsed="$(python3 -c "$PARSE_PY" "$sarif" "$repo")"
  local n blind
  n="$(printf '%s' "$parsed" | python3 -c 'import json,sys; print(json.load(sys.stdin)["findings"])')"
  blind="$(printf '%s' "$parsed" | python3 -c 'import json,sys; print("1" if json.load(sys.stdin)["blind"] else "0")')"

  # Append immediately. Buffering results until the end loses everything on a crash.
  emit "$RESULTS" "$(printf '%s' "$parsed" | python3 -c '
import json,sys
d=json.load(sys.stdin); d.pop("rows",None)
d["mode"]=sys.argv[1]; d["started"]=sys.argv[2]
print(json.dumps(d))' "$acquired" "$started")"

  printf '%s' "$parsed" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for r in d["rows"]:
    msg = " ".join(r["message"].split())[:200]
    print("\t".join([d["repo"], r["rule"], r["source"], r["sink"], msg]))
' | while IFS= read -r row; do emit "$FINDINGS" "$row"; done

  local tag=""; [[ "$blind" == "1" ]] && tag="  [BLIND — zero here means no sinks, not no bugs]"
  echo "  [$repo] $n findings$tag" >&2

  [[ $KEEP_DB -eq 1 ]] || rm -rf "$work"
  return 0
}

# ---------------------------------------------------------------- driver

mapfile -t REPOS < <(
  sed 's/#.*//' "$REPO_LIST" \
  | awk '{print $1}' \
  | grep -E '^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$' \
  | awk '!seen[$0]++'
)

if [[ $RESUME -eq 1 && -s "$RESULTS" ]]; then
  mapfile -t DONE < <(python3 -c '
import json,sys
for line in open(sys.argv[1]):
    line=line.strip()
    if not line: continue
    try: print(json.loads(line)["repo"])
    except Exception: pass
' "$RESULTS")
  declare -A seen=()
  for d in "${DONE[@]:-}"; do seen["$d"]=1; done
  REMAINING=()
  for r in "${REPOS[@]}"; do [[ -n "${seen[$r]:-}" ]] || REMAINING+=("$r"); done
  echo "resume: ${#DONE[@]} already recorded, ${#REMAINING[@]} to go" >&2
  REPOS=("${REMAINING[@]:-}")
fi

TOTAL=${#REPOS[@]}
if [[ $TOTAL -eq 0 ]]; then echo "nothing to do" >&2; else
  echo "scanning $TOTAL repos with $JOBS workers -> $OUTDIR" >&2
  i=0
  for repo in "${REPOS[@]}"; do
    while [[ "$(jobs -rp | wc -l)" -ge "$JOBS" ]]; do wait -n 2>/dev/null || sleep 1; done
    i=$((i+1))
    echo "[$i/$TOTAL] $repo" >&2
    scan_one "$((i % JOBS))" "$repo" &
  done
  wait
fi

# ---------------------------------------------------------------- summary

python3 - "$RESULTS" "$FINDINGS" > "$OUTDIR/summary.md" <<'PYEOF'
import json, sys, collections

results, findings = sys.argv[1], sys.argv[2]
rows = []
for line in open(results):
    line = line.strip()
    if line:
        try: rows.append(json.loads(line))
        except Exception: pass

by_status = collections.Counter(r.get("status", "?") for r in rows)
ok = [r for r in rows if r.get("status") == "ok"]
blind = [r for r in ok if r.get("blind")]
withf = [r for r in ok if r.get("findings", 0) > 0]
total = sum(r.get("findings", 0) for r in ok)

rules = collections.Counter()
for line in open(findings):
    p = line.rstrip("\n").split("\t")
    if len(p) >= 2 and p[0] != "repo":
        rules[p[1]] += 1

out = []
out.append("# Scan summary\n")
out.append(f"**{len(ok)} repos analysed · {total} findings · {len(withf)} repos with findings · {len(blind)} blind**\n")

out.append("\n## Coverage\n")
out.append("| Status | Repos |\n|---|---:|")
for k, v in by_status.most_common():
    out.append(f"| {k} | {v} |")
out.append(f"| **total** | **{len(rows)}** |")

out.append("\n> A *blind* repo resolved no custom-resource type. Both queries lose their")
out.append("> sinks there, so a zero is the absence of sinks, not the absence of bugs.")
out.append("> Never count these as clean.\n")

if rules:
    out.append("\n## Findings by rule\n")
    out.append("| Rule | Findings |\n|---|---:|")
    for k, v in rules.most_common():
        out.append(f"| `{k}` | {v} |")

if withf:
    out.append("\n## Repos with findings\n")
    out.append("| Repo | Findings |\n|---|---:|")
    for r in sorted(withf, key=lambda r: -r["findings"]):
        out.append(f"| `{r['repo']}` | {r['findings']} |")

if blind:
    out.append("\n## Blind repos — no data, not clean\n")
    for r in sorted(blind, key=lambda r: r["repo"]):
        out.append(f"- `{r['repo']}`")

out.append("\n## Next\n")
out.append("Findings are raw dataflow, not vulnerabilities. Adjudicate each on privilege")
out.append("escalation: an operator is a confused deputy, so a path only matters if it")
out.append("reaches something the custom-resource author could not already reach. Read the")
out.append("CRD type first — if the field is designed to do what the injection does, the")
out.append("delta is empty and there is no issue.")

print("\n".join(out))
PYEOF

echo >&2
echo "done — $OUTDIR/summary.md" >&2
sed -n '3p' "$OUTDIR/summary.md" >&2

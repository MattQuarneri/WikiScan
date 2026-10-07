#!/bin/bash
# OPT-00 benchmark harness: build a keyword index on the synthetic fixture and
# report wall-clock (median of N runs), pages, matches, peak RSS, and a
# checksum of the sorted (title, offset) match list (behavior-preservation gate).
#
# Usage: bench/bench.sh <keyword> [label]
# Env:   WIKISCAN_BIN (default ./target/release/wikiscan)
#        FIXTURE      (default bench/fixture.xml.bz2; generated if missing)
#        BENCH_RUNS   (default 3)
set -u

BIN="${WIKISCAN_BIN:-./target/release/wikiscan}"
FIX="${FIXTURE:-bench/fixture.xml.bz2}"
KW="$1"
LABEL="${2:-$1}"
RUNS="${BENCH_RUNS:-3}"

if [ ! -f "$FIX" ]; then
    echo "fixture missing, generating: $FIX" >&2
    python3 bench/gen_fixture.py "$FIX" >&2
fi

OUTDIR="$(mktemp -d)"
trap 'rm -rf "$OUTDIR"' EXIT

declare -a WALLS=()
CHECKSUM=""
PAGES=""
MATCHES=""
RSS=0

for i in $(seq 1 "$RUNS"); do
    rm -f "$OUTDIR/out.idx"
    START="$(date +%s.%N)"
    # /nonexistent-ms.bz2 forces the header-scan fallback path (no multistream index)
    "$BIN" build-idx "$FIX" /nonexistent-ms.bz2 "$KW" \
        --out "$OUTDIR/out.idx" >"$OUTDIR/run$i.log" 2>&1 &
    PID=$!
    PEAK=0
    while kill -0 "$PID" 2>/dev/null; do
        if [ -r "/proc/$PID/status" ]; then
            HWM="$(awk '/VmHWM/ {print $2}' "/proc/$PID/status")"
            if [ -n "$HWM" ] && [ "$HWM" -gt "$PEAK" ]; then PEAK="$HWM"; fi
        fi
        sleep 0.05
    done
    wait "$PID"
    END="$(date +%s.%N)"
    WALL="$(awk -v s="$START" -v e="$END" 'BEGIN {printf "%.3f", e - s}')"
    WALLS+=("$WALL")
    if [ ! -f "$OUTDIR/out.idx" ]; then
        echo "RUN $i FAILED to produce out.idx; log:" >&2
        tail -5 "$OUTDIR/run$i.log" >&2
        exit 1
    fi
    CS="$(sort "$OUTDIR/out.idx" | sha256sum | cut -d' ' -f1)"
    if [ -z "$CHECKSUM" ]; then
        CHECKSUM="$CS"
    elif [ "$CHECKSUM" != "$CS" ]; then
        echo "NONDETERMINISM: run $i checksum $CS != $CHECKSUM" >&2
        CHECKSUM="MISMATCH"
    fi
    PAGES="$(grep -a '^Scanned pages:' "$OUTDIR/run$i.log" | awk '{print $3}')"
    MATCHES="$(grep -a '^Matches:' "$OUTDIR/run$i.log" | awk '{print $2}')"
    if [ "$PEAK" -gt "$RSS" ]; then RSS="$PEAK"; fi
done

MEDIAN="$(printf '%s\n' "${WALLS[@]}" | sort -n | sed -n "$(((RUNS + 1) / 2))p")"
PPS="$(awk -v p="$PAGES" -v m="$MEDIAN" 'BEGIN {printf "%.1f", p / m}')"

printf 'keyword=%s label=%s runs=%d wall_median_s=%s pages=%s matches=%s pages_per_s=%s rss_max_kb=%s checksum=%s\n' \
    "$KW" "$LABEL" "$RUNS" "$MEDIAN" "$PAGES" "$MATCHES" "$PPS" "$RSS" "$CHECKSUM"

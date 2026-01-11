#!/usr/bin/env bash
set -euo pipefail

# Sync helper for EURO96 DOSBox shared folder.
# Default shared folder path (macOS):
DEFAULT_DOSBOX_EURO96_DIR="/Users/torarinbjarko/Documents/DosBox/dosbox-x/c/EURO96"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC_DIR="$ROOT_DIR/dosbox-sync/EURO96"

usage() {
  cat <<'USAGE'
Usage:
  tools/dosbox_sync_euro96.sh [--dir <DOSBOX_EURO96_DIR>] <command> [args]

Commands:
  push                Copy dosbox-sync/EURO96/{bdata.c,entry.c,blst.h,build.bat} into DOSBox folder
  pull                Copy {bdata.c,entry.c,blst.h,build.bat} from DOSBox folder into dosbox-sync/EURO96/
  tail [N]            Tail the last N lines (default 120) of DOSRETRA.TXT
  audio [N]           Show last N matching lines for AUDIO/ENTRY markers from DOSRETRA.TXT
  files               List trace/log files in the DOSBox folder

Examples:
  tools/dosbox_sync_euro96.sh push
  tools/dosbox_sync_euro96.sh --dir "/path/to/dosbox-x/c/EURO96" push
  tools/dosbox_sync_euro96.sh audio 200
USAGE
}

DOSBOX_DIR="$DEFAULT_DOSBOX_EURO96_DIR"

if [[ "${1:-}" == "--dir" ]]; then
  DOSBOX_DIR="${2:-}"
  shift 2
fi

cmd="${1:-}"
shift || true

need_dir() {
  if [[ ! -d "$DOSBOX_DIR" ]]; then
    echo "ERROR: DOSBox folder not found: $DOSBOX_DIR" >&2
    exit 2
  fi
}

case "$cmd" in
  push)
    need_dir
    mkdir -p "$SRC_DIR"
    for f in bdata.c entry.c blst.h build.bat; do
      if [[ -f "$SRC_DIR/$f" ]]; then
        cp "$SRC_DIR/$f" "$DOSBOX_DIR/$f"
        echo "PUSH: $f"
      else
        echo "SKIP: missing in repo: $SRC_DIR/$f" >&2
      fi
    done
    ;;

  pull)
    need_dir
    mkdir -p "$SRC_DIR"
    for f in bdata.c entry.c blst.h build.bat; do
      if [[ -f "$DOSBOX_DIR/$f" ]]; then
        cp "$DOSBOX_DIR/$f" "$SRC_DIR/$f"
        echo "PULL: $f"
      else
        echo "SKIP: missing in DOSBox folder: $DOSBOX_DIR/$f" >&2
      fi
    done
    ;;

  files)
    need_dir
    (cd "$DOSBOX_DIR" && ls -la | egrep -i "DOSRETR|OUT\\.TXT|LOG\\.TXT|RC\\.TXT|STA\\.TXT" || true)
    ;;

  tail)
    need_dir
    n="${1:-120}"
    trace="$DOSBOX_DIR/DOSRETRA.TXT"
    if [[ ! -f "$trace" ]]; then
      echo "NO TRACE: $trace" >&2
      exit 3
    fi
    tail -n "$n" "$trace"
    ;;

  audio)
    need_dir
    n="${1:-200}"
    trace="$DOSBOX_DIR/DOSRETRA.TXT"
    if [[ ! -f "$trace" ]]; then
      echo "NO TRACE: $trace" >&2
      exit 3
    fi
    # Print only the markers we care about.
    egrep -n "^(AUDIO:|ENTRY:)" "$trace" | tail -n "$n" || true
    ;;

  ""|-h|--help|help)
    usage
    ;;

  *)
    echo "Unknown command: $cmd" >&2
    usage
    exit 1
    ;;
esac

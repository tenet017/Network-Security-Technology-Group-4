#!/usr/bin/env bash
# One command: CSVs -> figures + data tables + filled main.tex -> compiled PDF.
# Usage: bash build_paper.sh <results_csv_dir> <overleaf_dir>
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
RES="$(cd "$1" && pwd)"            # dir holding all result CSVs
OVL="$(cd "$2" && pwd)"           # overleaf-shared working copy
OUTR="$OVL/results"               # where the paper includes figures/tables from

mkdir -p "$OUTR/tables"
python3 "$HERE/make_figures.py"        --results "$RES" --out "$OUTR"
python3 "$HERE/build_paper_numbers.py" --results "$RES" --out "$OUTR/tables"
python3 "$HERE/fill_tokens.py" --template "$OVL/main.tex.in" \
        --out "$OVL/main.tex" --tokens "$OUTR/paper_tokens.json"

echo "== compiling with tectonic =="
( cd "$OVL" && tectonic main.tex >/dev/null 2>&1 && \
  echo "pages: $(pdfinfo main.pdf | awk '/Pages/{print $2}')" )
echo "done."

"""Render main.tex from the main.tex.in template and paper_tokens.json.

Reads the «token» template, substitutes real values, and writes the final
main.tex that Overleaf compiles. Fails loudly if any token has no value or
any «...» remains, so the paper can never ship an unfilled placeholder.

    python fill_tokens.py --template ../../overleaf-shared/main.tex.in \
                          --out ../../overleaf-shared/main.tex \
                          --tokens ../results/paper_tokens.json
"""
import argparse
import json
import re
import sys
from pathlib import Path


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--template", type=Path, required=True)
    ap.add_argument("--out", type=Path, required=True)
    ap.add_argument("--tokens", type=Path, required=True)
    args = ap.parse_args()
    tok = json.loads(args.tokens.read_text())
    text = args.template.read_text()
    used = set(re.findall(r"«([^»]+)»", text))
    missing = used - set(tok)
    if missing:
        sys.exit(f"ERROR: no value for tokens: {sorted(missing)}")
    for k, v in tok.items():
        text = text.replace(f"«{k}»", str(v))
    leftover = re.findall(r"«[^»]+»", text)
    if leftover:
        sys.exit(f"ERROR: unfilled placeholders remain: {leftover}")
    args.out.write_text(text)
    print(f"filled {len(used)} distinct tokens -> {args.out}")


if __name__ == "__main__":
    main()

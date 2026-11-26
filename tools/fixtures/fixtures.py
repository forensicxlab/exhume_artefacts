#!/usr/bin/env python3
"""Check committed vectors or replay independent generators in a temporary tree."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile

ROOT=Path(__file__).resolve().parents[2]
MANIFEST=Path(__file__).with_name("manifest.json")

def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command",choices=["check","verify","regenerate"])
    parser.add_argument("--indexer",type=Path,help="Also check/sync the independent indexer fixture copies")
    args=parser.parse_args()
    manifest=json.loads(MANIFEST.read_text())
    if args.command in ("verify","regenerate"):
        with tempfile.TemporaryDirectory(prefix="exhume-fixtures-") as temporary:
            staged=Path(temporary)
            for directory in ("src","tools","tests"):
                shutil.copytree(ROOT/directory,staged/directory,ignore=shutil.ignore_patterns("__pycache__"))
            for generator in manifest["generators"]:
                interpreter="node" if generator.endswith(".mjs") else sys.executable
                subprocess.run([interpreter,str(staged/"tools/fixtures"/generator)],check=True)
            mismatches=[name for name in manifest["deterministic_outputs"] if (staged/name).read_bytes()!=(ROOT/name).read_bytes()]
            if args.command=="verify" and mismatches:
                raise SystemExit("Reference regeneration differs: "+", ".join(mismatches))
            if args.command=="regenerate":
                for name in manifest["deterministic_outputs"]:
                    shutil.copyfile(staged/name,ROOT/name)
                manifest["sha256"]={name:digest(ROOT/name) for name in manifest["sha256"]}
                MANIFEST.write_text(json.dumps(manifest,indent=2)+"\n")
    mismatches=[name for name,expected in manifest["sha256"].items() if not (ROOT/name).is_file() or digest(ROOT/name)!=expected]
    if mismatches:
        raise SystemExit("Fixture manifest differs: "+", ".join(mismatches))
    if args.indexer:
        command="sync" if args.command=="regenerate" else args.command
        subprocess.run([sys.executable,str(args.indexer/"tools/fixtures.py"),command,"--artefacts",str(ROOT)],check=True)
    print(f"Verified {len(manifest['sha256'])} fixture hashes; {args.command} completed.")

if __name__=="__main__":
    main()

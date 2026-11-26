#!/usr/bin/env python3
"""Create an isolated, synthetic Keychain with Apple's CLI on a disposable Mac.

Usage: python3 tests/generate_keychain_fixture.py /private/tmp/new-fixture-directory
All passwords below are public test values. Randomness changes the output hash.
"""

import hashlib
import os
from pathlib import Path
import shlex
import subprocess
import sys

SECURITY = "/usr/bin/security"
PASSWORD = "exhume synthetic fixture password"
SERVICE = "Exhume Keychain Fixture"
ITEMS = {
    "fixture-alpha": "SYNTHETIC-ALPHA-SECRET",
    "fixture-beta": "SYNTHETIC-BETA-SECRET",
}


def security(*arguments):
    return subprocess.run(
        [SECURITY, *arguments], check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ).stdout


def main():
    if sys.platform != "darwin" or len(sys.argv) != 2:
        raise SystemExit("Run on a disposable macOS lab with one new output-directory path")
    os.umask(0o077)
    directory = Path(sys.argv[1]).resolve()
    directory.mkdir(mode=0o700)
    keychain = str(directory / "synthetic.keychain-db")
    search_list = security("list-keychains", "-d", "user")
    original_paths = shlex.split(search_list.decode())
    default = security("default-keychain", "-d", "user")
    try:
        security("create-keychain", "-p", PASSWORD, keychain)
        for account, value in ITEMS.items():
            security("add-generic-password", "-a", account, "-s", SERVICE,
                     "-w", value, "-T", SECURITY, keychain)
            actual = security("find-generic-password", "-a", account, "-s", SERVICE,
                              "-w", keychain)
            if actual != value.encode() + b"\n":
                raise RuntimeError("native CLI did not recover the expected synthetic value")
        security("lock-keychain", keychain)
        internet_keychain = str(directory / "synthetic-internet.keychain-db")
        security("create-keychain", "-p", PASSWORD, internet_keychain)
        security("add-internet-password", "-a", "fixture-internet", "-s", "fixture.invalid",
                 "-r", "htps", "-P", "443", "-p", "/exhume-fixture",
                 "-w", "SYNTHETIC-INTERNET-SECRET", "-T", SECURITY, internet_keychain)
        actual = security("find-internet-password", "-a", "fixture-internet", "-s", "fixture.invalid",
                          "-w", internet_keychain)
        if actual != b"SYNTHETIC-INTERNET-SECRET\n":
            raise RuntimeError("native CLI did not recover the expected synthetic internet value")
        security("lock-keychain", internet_keychain)
        partition_directory = directory / "partition" / "Library" / "Keychains"
        partition_directory.mkdir(mode=0o700, parents=True)
        partition_keychain = str(partition_directory / "synthetic-partition.keychain-db")
        security("create-keychain", "-p", PASSWORD, partition_keychain)
        security("add-generic-password", "-a", "fixture-partition", "-s", "Exhume Partition Fixture",
                 "-w", "SYNTHETIC-PARTITION-SECRET", "-T", SECURITY, partition_keychain)
        actual = security("find-generic-password", "-a", "fixture-partition", "-s", "Exhume Partition Fixture",
                          "-w", partition_keychain)
        if actual != b"SYNTHETIC-PARTITION-SECRET\n":
            raise RuntimeError("native CLI did not recover the expected synthetic partition value")
        security("lock-keychain", partition_keychain)
    finally:
        security("list-keychains", "-d", "user", "-s", *original_paths)
        if security("default-keychain", "-d", "user") != default:
            security("default-keychain", "-d", "user", "-s", *shlex.split(default.decode()))
        if security("list-keychains", "-d", "user") != search_list:
            raise RuntimeError("Keychain search-list restoration did not verify")
    for fixture in (keychain, internet_keychain, partition_keychain):
        blob = Path(fixture).read_bytes()
        print(f"Verified and locked synthetic fixture: {fixture}")
        print(f"bytes={len(blob)} sha256={hashlib.sha256(blob).hexdigest()}")


if __name__ == "__main__":
    main()

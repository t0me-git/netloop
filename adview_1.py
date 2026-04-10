#!/usr/bin/env python3
"""adview_1: BloodHound CE collection triggered by cracked credentials."""

from __future__ import annotations

import argparse
import select
import shlex
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple


@dataclass
class BloodhoundConfig:
    domain: str
    dc_ip: str


@dataclass
class BloodhoundJob:
    user: str
    command: str
    status: str = "pending"
    proc: Optional[subprocess.Popen] = None
    output_lines: List[str] = field(default_factory=list)


@dataclass
class BloodhoundState:
    config: Optional[BloodhoundConfig] = None
    jobs: List[BloodhoundJob] = field(default_factory=list)
    active_job_index: Optional[int] = None
    pending: List[Tuple[str, str]] = field(default_factory=list)
    triggered_users: set = field(default_factory=set)


def configure_args(parser: argparse.ArgumentParser) -> None:
    """Add BloodHound-related CLI arguments to an existing parser."""
    parser.add_argument(
        "-bh", "--bloodhound",
        action="store_true",
        help="auto-run BloodHound CE collection on cracked credentials",
    )
    parser.add_argument(
        "--domain",
        help="AD domain for BloodHound (e.g. north.sevenkingdoms.local)",
    )
    parser.add_argument(
        "--dc-ip",
        help="domain controller IP for BloodHound",
    )


def resolve_config(
    parsed_args: argparse.Namespace,
    ntlmv2_cfg: dict,
    prompt_fn: Callable[[str, str], str],
) -> Optional[BloodhoundConfig]:
    """Resolve BloodHound config from CLI args and interactive prompts.

    Returns None when -bh is not set.
    """
    if not getattr(parsed_args, "bloodhound", False):
        return None

    domain = getattr(parsed_args, "domain", None)
    if domain is None:
        domain = prompt_fn("Domain", ntlmv2_cfg.get("bloodhound_domain", ""))

    dc_ip = getattr(parsed_args, "dc_ip", None)
    if dc_ip is None:
        dc_ip = prompt_fn("DC IP", ntlmv2_cfg.get("bloodhound_dc_ip", ""))

    return BloodhoundConfig(domain=domain, dc_ip=dc_ip)


def save_to_cfg(config: BloodhoundConfig, ntlmv2_cfg: dict) -> None:
    """Persist BloodHound settings into the ntlmv2 config section."""
    ntlmv2_cfg["bloodhound_domain"] = config.domain
    ntlmv2_cfg["bloodhound_dc_ip"] = config.dc_ip


def queue_run(state: BloodhoundState, username: str, password: str) -> None:
    """Queue a BloodHound collection for a newly cracked user."""
    if state.config is None:
        return
    canon = username.strip().lower()
    if canon in state.triggered_users:
        return
    state.triggered_users.add(canon)
    state.pending.append((username, password))


def start_next(state: BloodhoundState, session_dir: Path, verbose: bool = False) -> None:
    """Start the next pending BloodHound job if no job is currently active."""
    if state.config is None or state.active_job_index is not None or not state.pending:
        return

    bh_path = shutil.which("bloodhound-ce-python")
    if not bh_path:
        username, _ = state.pending.pop(0)
        state.jobs.append(BloodhoundJob(
            user=username,
            command="bloodhound-ce-python (not found in PATH)",
            status="error (not found)",
        ))
        return

    username, password = state.pending.pop(0)
    output_dir = session_dir / "bloodhound_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    cmd = [
        bh_path,
        "-d", state.config.domain,
        "-u", username,
        "-p", password,
        "-ns", state.config.dc_ip,
        "-c", "All",
    ]
    cmd_text = " ".join(shlex.quote(part) for part in cmd)

    job = BloodhoundJob(user=username, command=cmd_text, status="running")
    job.proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        text=True,
        cwd=str(output_dir),
        bufsize=1,
        start_new_session=True,
    )
    state.jobs.append(job)
    state.active_job_index = len(state.jobs) - 1


def poll(state: BloodhoundState, verbose: bool = False) -> None:
    """Poll the active BloodHound job for output and detect completion."""
    if state.active_job_index is None:
        return
    job = state.jobs[state.active_job_index]
    if job.proc is None:
        return

    if job.proc.stdout is not None:
        fd = job.proc.stdout.fileno()
        while True:
            ready, _, _ = select.select([fd], [], [], 0)
            if not ready:
                break
            line = job.proc.stdout.readline()
            if not line:
                break
            stripped = line.rstrip("\n")
            job.output_lines.append(stripped)
            if verbose:
                print(stripped, flush=True)

    if job.proc.poll() is not None:
        if job.proc.stdout:
            for line in job.proc.stdout:
                stripped = line.rstrip("\n")
                job.output_lines.append(stripped)
                if verbose:
                    print(stripped, flush=True)
        rc = job.proc.wait()
        job.status = "done" if rc == 0 else f"error ({rc})"
        job.proc = None
        state.active_job_index = None


def cleanup(state: BloodhoundState) -> None:
    """Terminate any active BloodHound process."""
    if state.active_job_index is not None:
        job = state.jobs[state.active_job_index]
        if job.proc and job.proc.poll() is None:
            job.proc.terminate()
            try:
                job.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                job.proc.kill()
                job.proc.wait()
            job.status = "interrupted"
            job.proc = None
        state.active_job_index = None


def is_idle(state: BloodhoundState) -> bool:
    """Return True when no BH work is pending or running."""
    return state.active_job_index is None and not state.pending


def render_dashboard_lines(state: BloodhoundState) -> List[str]:
    """Return lines for the live dashboard BloodHound section."""
    if state.config is None:
        return []

    lines = ["", "BloodHound CE:"]
    if not state.jobs and not state.pending:
        lines.append("  Waiting for cracked credentials...")
        return lines

    for idx, job in enumerate(state.jobs, start=1):
        if job.status == "running":
            lines.append(f"  {idx}. {job.user} - collecting...")
        else:
            lines.append(f"  {idx}. {job.user} - {job.status}")

    if state.pending:
        lines.append(f"  Queued: {len(state.pending)}")

    return lines


def render_final_summary(state: BloodhoundState) -> List[str]:
    """Return summary lines printed after the run completes."""
    if state.config is None:
        return []

    lines = ["\nBloodHound CE:"]
    if not state.jobs:
        lines.append("- No collections triggered")
        return lines

    completed = sum(1 for j in state.jobs if j.status == "done")
    errors = sum(1 for j in state.jobs if j.status.startswith("error"))
    lines.append(f"- Collections completed: {completed}")
    if errors:
        lines.append(f"- Collection errors: {errors}")

    for idx, job in enumerate(state.jobs, start=1):
        lines.append(f"  {idx}. {job.user}: {job.status}")

    return lines

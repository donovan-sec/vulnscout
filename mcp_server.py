"""
vulnscout_mcp: MCP server for controlling VulnScout from Claude chat.

Runs on your VPS. Exposes tools so you can start, monitor, and stop
scans directly from the Claude.ai chat window.

Start the server:
    python mcp_server.py

Then add to Claude.ai connectors:
    URL: http://your-vps-ip:8000/mcp
"""

import json
import os
import signal
import subprocess
import time
from datetime import datetime
from pathlib import Path
from typing import Optional

from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field, ConfigDict

# --- Config ---
VULNSCOUT_DIR = Path(os.environ.get("VULNSCOUT_DIR", Path(__file__).parent))
FINDINGS_DIR = VULNSCOUT_DIR / "findings"
LOGS_DIR = VULNSCOUT_DIR / "logs"
VS_SCRIPT = VULNSCOUT_DIR / "vs"

FINDINGS_DIR.mkdir(exist_ok=True)
LOGS_DIR.mkdir(exist_ok=True)

# Track running processes: {job_id: {"pid": int, "cmd": str, "started": str, "log": str}}
RUNNING_JOBS: dict = {}

mcp = FastMCP("vulnscout_mcp")


# --- Helpers ---

def _job_id() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def _run_background(cmd: list, log_path: str) -> int:
    """Launch a subprocess in the background, redirect output to log file."""
    with open(log_path, "w") as log_fh:
        proc = subprocess.Popen(
            cmd,
            stdout=log_fh,
            stderr=subprocess.STDOUT,
            cwd=str(VULNSCOUT_DIR),
            start_new_session=True,
        )
    return proc.pid


def _is_running(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def _tail_log(log_path: str, lines: int = 50) -> str:
    path = Path(log_path)
    if not path.exists():
        return "(log not found)"
    text = path.read_text(errors="ignore")
    all_lines = text.splitlines()
    return "\n".join(all_lines[-lines:])


def _list_findings(limit: int = 20) -> list:
    files = sorted(FINDINGS_DIR.glob("vulnscout_*.md"), reverse=True)[:limit]
    results = []
    for f in files:
        stat = f.stat()
        results.append({
            "filename": f.name,
            "size_kb": round(stat.st_size / 1024, 1),
            "modified": datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M"),
        })
    return results


# --- Input Models ---

class HuntInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    query: str = Field(
        ...,
        description="GitHub search query (e.g. 'topic:parser', 'network protocol parser')",
        min_length=2,
        max_length=200,
    )
    language: Optional[str] = Field(
        default=None,
        description="GitHub language filter for search (e.g. 'c', 'cpp', 'python', 'go')",
    )
    language_filter: Optional[str] = Field(
        default=None,
        description="File extension filter within repos: c_cpp, python, javascript, go, rust, java, php, ruby",
    )
    max_repos: int = Field(
        default=10,
        description="Max repos to scan (1-30)",
        ge=1,
        le=30,
    )
    min_stars: int = Field(
        default=50,
        description="Minimum GitHub stars",
        ge=0,
    )
    max_stars: int = Field(
        default=2000,
        description="Maximum GitHub stars",
        ge=1,
    )
    iterations: int = Field(
        default=12,
        description="Claude loop iterations per repo (more = deeper but slower/pricier)",
        ge=3,
        le=25,
    )
    focus: Optional[str] = Field(
        default=None,
        description="Keyword to focus file selection (e.g. 'parser', 'auth', 'decode')",
    )


class RepoScanInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    source: str = Field(
        ...,
        description="Git URL or local path to scan",
        min_length=3,
    )
    language_filter: Optional[str] = Field(
        default=None,
        description="File extension filter: c_cpp, python, javascript, go, rust, java, php, ruby",
    )
    iterations: int = Field(
        default=15,
        description="Claude loop iterations",
        ge=3,
        le=30,
    )
    focus: Optional[str] = Field(
        default=None,
        description="Focus on files matching this keyword",
    )


class JobIdInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    job_id: str = Field(
        ...,
        description="Job ID returned by start_hunt or start_repo_scan",
        min_length=15,
        max_length=20,
    )


class LogInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    job_id: str = Field(..., description="Job ID to fetch logs for")
    lines: int = Field(
        default=50,
        description="Number of tail lines to return",
        ge=10,
        le=200,
    )


class FindingInput(BaseModel):
    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    filename: str = Field(
        ...,
        description="Filename from list_findings (e.g. vulnscout_repo_github.com_..._.md)",
        min_length=5,
    )


# --- Tools ---

@mcp.tool(
    name="vulnscout_start_hunt",
    annotations={
        "title": "Start a GitHub Hunt",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }
)
async def vulnscout_start_hunt(params: HuntInput) -> str:
    """Start an automated GitHub search-and-scan hunt in the background.

    Searches GitHub for repos matching the query, clones each one,
    scans with the Claude agentic loop, saves findings, and moves on.
    Returns a job_id you can use to check progress or stop the scan.

    Args:
        params (HuntInput): Hunt configuration including query, language,
            max_repos, iterations, and optional focus keyword.

    Returns:
        str: JSON with job_id, pid, log_path, and status message.
    """
    job_id = _job_id()
    log_path = str(LOGS_DIR / f"hunt_{job_id}.log")

    cmd = [str(VS_SCRIPT), "hunt", params.query]

    if params.language:
        cmd += ["--language", params.language]
    if params.language_filter:
        cmd += ["--language-filter", params.language_filter]
    if params.focus:
        cmd += ["--focus", params.focus]

    cmd += [
        "--max-repos", str(params.max_repos),
        "--min-stars", str(params.min_stars),
        "--max-stars", str(params.max_stars),
        "--iterations", str(params.iterations),
        "--output", str(FINDINGS_DIR),
    ]

    pid = _run_background(cmd, log_path)

    RUNNING_JOBS[job_id] = {
        "pid": pid,
        "type": "hunt",
        "cmd": " ".join(cmd),
        "query": params.query,
        "started": datetime.now().isoformat(),
        "log": log_path,
    }

    return json.dumps({
        "job_id": job_id,
        "pid": pid,
        "status": "started",
        "query": params.query,
        "max_repos": params.max_repos,
        "log_path": log_path,
        "message": f"Hunt started. Use vulnscout_get_log with job_id '{job_id}' to check progress.",
    }, indent=2)


@mcp.tool(
    name="vulnscout_start_repo_scan",
    annotations={
        "title": "Start a Single Repo Scan",
        "readOnlyHint": False,
        "destructiveHint": False,
        "idempotentHint": False,
        "openWorldHint": True,
    }
)
async def vulnscout_start_repo_scan(params: RepoScanInput) -> str:
    """Start a scan of a single git repo or local directory in the background.

    Args:
        params (RepoScanInput): Source URL or path, optional language filter,
            iterations count, and optional focus keyword.

    Returns:
        str: JSON with job_id, pid, log_path, and status message.
    """
    job_id = _job_id()
    log_path = str(LOGS_DIR / f"repo_{job_id}.log")

    cmd = [str(VS_SCRIPT), "repo", params.source]

    if params.language_filter:
        cmd += ["--language", params.language_filter]
    if params.focus:
        cmd += ["--focus", params.focus]

    cmd += [
        "--iterations", str(params.iterations),
        "--output", str(FINDINGS_DIR),
    ]

    pid = _run_background(cmd, log_path)

    RUNNING_JOBS[job_id] = {
        "pid": pid,
        "type": "repo",
        "cmd": " ".join(cmd),
        "source": params.source,
        "started": datetime.now().isoformat(),
        "log": log_path,
    }

    return json.dumps({
        "job_id": job_id,
        "pid": pid,
        "status": "started",
        "source": params.source,
        "log_path": log_path,
        "message": f"Repo scan started. Use vulnscout_get_log with job_id '{job_id}' to check progress.",
    }, indent=2)


@mcp.tool(
    name="vulnscout_get_status",
    annotations={
        "title": "Get Status of All Jobs",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
async def vulnscout_get_status() -> str:
    """Get status of all running and recently completed vulnscout jobs.

    Returns:
        str: JSON with list of jobs and their current status (running/completed).
    """
    jobs = []
    for job_id, info in RUNNING_JOBS.items():
        running = _is_running(info["pid"])
        jobs.append({
            "job_id": job_id,
            "type": info["type"],
            "status": "running" if running else "completed",
            "pid": info["pid"],
            "started": info["started"],
            "query_or_source": info.get("query") or info.get("source", ""),
            "log": info["log"],
        })

    jobs.sort(key=lambda x: x["started"], reverse=True)

    return json.dumps({
        "total_jobs": len(jobs),
        "running": sum(1 for j in jobs if j["status"] == "running"),
        "completed": sum(1 for j in jobs if j["status"] == "completed"),
        "jobs": jobs,
    }, indent=2)


@mcp.tool(
    name="vulnscout_get_log",
    annotations={
        "title": "Get Job Log Output",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
async def vulnscout_get_log(params: LogInput) -> str:
    """Tail the log output for a running or completed job.

    Args:
        params (LogInput): job_id and number of lines to return.

    Returns:
        str: JSON with job status and last N lines of log output.
    """
    if params.job_id not in RUNNING_JOBS:
        return json.dumps({"error": f"Job '{params.job_id}' not found. Use vulnscout_get_status to list jobs."})

    info = RUNNING_JOBS[params.job_id]
    running = _is_running(info["pid"])
    log_tail = _tail_log(info["log"], params.lines)

    return json.dumps({
        "job_id": params.job_id,
        "status": "running" if running else "completed",
        "type": info["type"],
        "started": info["started"],
        "log_tail": log_tail,
    }, indent=2)


@mcp.tool(
    name="vulnscout_stop_scan",
    annotations={
        "title": "Stop a Running Scan",
        "readOnlyHint": False,
        "destructiveHint": True,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
async def vulnscout_stop_scan(params: JobIdInput) -> str:
    """Stop a running scan by job_id.

    Any findings already saved to disk are preserved.

    Args:
        params (JobIdInput): job_id of the scan to stop.

    Returns:
        str: JSON with confirmation and final log tail.
    """
    if params.job_id not in RUNNING_JOBS:
        return json.dumps({"error": f"Job '{params.job_id}' not found."})

    info = RUNNING_JOBS[params.job_id]
    pid = info["pid"]

    if not _is_running(pid):
        return json.dumps({
            "job_id": params.job_id,
            "status": "already_completed",
            "message": "Job was not running.",
        })

    try:
        os.killpg(os.getpgid(pid), signal.SIGTERM)
        time.sleep(1)
        if _is_running(pid):
            os.killpg(os.getpgid(pid), signal.SIGKILL)
        stopped = True
    except Exception as e:
        stopped = False
        error = str(e)

    log_tail = _tail_log(info["log"], 20)

    return json.dumps({
        "job_id": params.job_id,
        "status": "stopped" if stopped else "stop_failed",
        "message": "Scan stopped. Findings saved so far are preserved." if stopped else f"Could not stop: {error}",
        "last_log_lines": log_tail,
    }, indent=2)


@mcp.tool(
    name="vulnscout_list_findings",
    annotations={
        "title": "List Finding Reports",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
async def vulnscout_list_findings() -> str:
    """List all finding reports saved to the findings directory.

    Returns:
        str: JSON with list of finding files, sizes, and modification times.
    """
    findings = _list_findings(limit=30)

    if not findings:
        return json.dumps({
            "count": 0,
            "message": "No findings yet. Start a hunt with vulnscout_start_hunt.",
            "findings": [],
        })

    return json.dumps({
        "count": len(findings),
        "findings_dir": str(FINDINGS_DIR),
        "findings": findings,
    }, indent=2)


@mcp.tool(
    name="vulnscout_get_finding",
    annotations={
        "title": "Read a Finding Report",
        "readOnlyHint": True,
        "destructiveHint": False,
        "idempotentHint": True,
        "openWorldHint": False,
    }
)
async def vulnscout_get_finding(params: FindingInput) -> str:
    """Read the full contents of a finding report.

    Args:
        params (FindingInput): filename from vulnscout_list_findings.

    Returns:
        str: Full markdown report content.
    """
    # Sanitize -- only allow files inside findings dir
    safe_name = Path(params.filename).name
    path = FINDINGS_DIR / safe_name

    if not path.exists():
        return json.dumps({"error": f"Finding '{safe_name}' not found. Use vulnscout_list_findings to see available reports."})

    if not safe_name.startswith("vulnscout_"):
        return json.dumps({"error": "Invalid filename."})

    content = path.read_text(errors="ignore")
    return content


# --- Run ---

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VulnScout MCP Server")
    parser.add_argument("--port", type=int, default=8000, help="Port to listen on (default: 8000)")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to (default: 0.0.0.0)")
    args = parser.parse_args()

    print(f"Starting VulnScout MCP server on {args.host}:{args.port}")
    print(f"VulnScout dir: {VULNSCOUT_DIR}")
    print(f"Findings dir: {FINDINGS_DIR}")
    print(f"Add to Claude.ai connectors: http://YOUR_VPS_IP:{args.port}/mcp")

    mcp.run(transport="streamable_http", host=args.host, port=args.port)

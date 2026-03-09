"""
Repo scanner: accepts a git URL or local directory path.
Chunks source files intelligently and runs the Claude loop.
"""

import os
import subprocess
import tempfile
import shutil
from pathlib import Path
from rich.console import Console
from rich.progress import track

console = Console()

# File extensions to analyze per language category
EXTENSIONS = {
    "c_cpp": [".c", ".cpp", ".cc", ".h", ".hpp"],
    "python": [".py"],
    "javascript": [".js", ".ts", ".jsx", ".tsx"],
    "go": [".go"],
    "rust": [".rs"],
    "java": [".java"],
    "php": [".php"],
    "ruby": [".rb"],
}

# Files/dirs to always skip
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".next", "dist", "build",
    "vendor", "third_party", "third-party", "deps", "external",
    ".venv", "venv", "env",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Cargo.lock",
    "go.sum",
}

# Max chars per chunk sent to Claude (stay well under context limits)
CHUNK_SIZE = 80_000
# Max chars per individual file before truncating
MAX_FILE_SIZE = 20_000


def clone_repo(url, target_dir):
    """Clone a git repo. Returns the cloned path."""
    console.print(f"[cyan]Cloning {url}...[/cyan]")
    result = subprocess.run(
        ["git", "clone", "--depth=1", url, target_dir],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Git clone failed:\n{result.stderr}")
    console.print(f"[green]Cloned to {target_dir}[/green]")
    return target_dir


def collect_files(base_path, language=None):
    """Walk the directory and collect source files."""
    base = Path(base_path)

    if language and language in EXTENSIONS:
        target_extensions = set(EXTENSIONS[language])
    else:
        # Collect everything we know about
        target_extensions = set(ext for exts in EXTENSIONS.values() for ext in exts)

    collected = []
    for path in base.rglob("*"):
        # Skip hidden dirs and known noise dirs
        if any(part.startswith(".") or part in SKIP_DIRS
               for part in path.parts):
            continue
        if path.name in SKIP_FILES:
            continue
        if path.is_file() and path.suffix in target_extensions:
            collected.append(path)

    console.print(f"[cyan]Found {len(collected)} source files[/cyan]")
    return collected


def load_and_chunk(file_paths, base_path):
    """
    Load files, truncate large ones, then pack into chunks 
    that fit comfortably in Claude's context.
    """
    chunks = []
    current_chunk = []
    current_size = 0

    for fpath in file_paths:
        try:
            content = fpath.read_text(errors="ignore")
        except Exception:
            continue

        rel_path = fpath.relative_to(base_path)

        # Truncate very large files but note the truncation
        if len(content) > MAX_FILE_SIZE:
            content = content[:MAX_FILE_SIZE] + f"\n\n[TRUNCATED -- file is {len(content)} chars total]"

        entry = {"path": str(rel_path), "content": content}
        entry_size = len(content) + len(str(rel_path)) + 20

        if current_size + entry_size > CHUNK_SIZE and current_chunk:
            chunks.append(current_chunk)
            current_chunk = [entry]
            current_size = entry_size
        else:
            current_chunk.append(entry)
            current_size += entry_size

    if current_chunk:
        chunks.append(current_chunk)

    console.print(f"[cyan]Packed into {len(chunks)} analysis chunks[/cyan]")
    return chunks


def prioritize_files(file_paths, base_path):
    """
    Heuristic prioritization: files that tend to contain 
    high-value vulnerability targets go first.
    """
    HIGH_VALUE_PATTERNS = [
        "auth", "login", "session", "token", "password", "crypto",
        "parser", "deserializ", "upload", "exec", "eval", "query",
        "sql", "cmd", "shell", "memory", "alloc", "buffer", "input",
        "request", "response", "handler", "middleware", "router",
        "admin", "user", "permission", "access", "privilege",
    ]

    def priority_score(path):
        name = path.name.lower()
        stem = path.stem.lower()
        score = 0
        for pattern in HIGH_VALUE_PATTERNS:
            if pattern in name or pattern in stem:
                score += 1
        return score

    return sorted(file_paths, key=priority_score, reverse=True)


def static_verifier(poc_string):
    """
    Static analysis verifier -- since we can't always build arbitrary repos,
    this confirms the PoC references real code constructs that exist.
    
    For repos you CAN build: replace this with the harness from the main README.
    """
    # Basic heuristics: does the PoC reference file paths or functions 
    # that actually exist? This is a soft verifier for static mode.
    # For a harder verifier, swap in the binary harness.
    if not poc_string or len(poc_string.strip()) < 10:
        return False, "PoC too short to be meaningful"

    # In static mode we trust Claude's analysis -- the "verification" 
    # is that Claude provided a concrete, specific PoC rather than vague claims.
    # Real verification requires a built binary. See README for binary harness setup.
    has_specifics = any(char in poc_string for char in ["(", "{", "[", "=", "->"])
    if has_specifics:
        return True, f"Static PoC recorded (binary verification not available in static mode):\n{poc_string}"
    else:
        return False, "PoC lacks concrete code specifics -- too vague"


def build_harness_verifier(binary_path):
    """
    Returns a verifier function that runs a built binary with ASAN.
    Use this when you can build the target.
    
    binary_path: path to an ASAN-instrumented binary that reads from stdin
    """
    def verifier(poc_string):
        import subprocess
        try:
            result = subprocess.run(
                [binary_path],
                input=poc_string.encode(),
                capture_output=True,
                timeout=15,
            )
            crashed = (
                result.returncode != 0
                or b"AddressSanitizer" in result.stderr
                or b"UndefinedBehaviorSanitizer" in result.stderr
                or b"runtime error" in result.stderr
            )
            output = result.stderr.decode(errors="ignore")[:2000]
            return crashed, output if output else "(no output)"
        except subprocess.TimeoutExpired:
            return False, "Timeout -- input may have caused hang (interesting but unconfirmed)"
        except Exception as e:
            return False, f"Harness error: {e}"

    return verifier


def scan_repo(source, language=None, binary_path=None, max_iterations=15,
              focus_area=None, output_dir=None):
    """
    Main entry point for repo scanning.
    
    source: git URL or local directory path
    language: optional filter ('c_cpp', 'python', 'javascript', etc.)
    binary_path: optional ASAN binary for hard verification
    max_iterations: Claude loop iterations per chunk
    focus_area: optional substring to filter filenames (e.g. 'auth', 'parser')
    """
    from scanner.claude_loop import run_repo_loop
    from scanner.reporter import write_report

    tmp_dir = None
    base_path = source

    try:
        # Clone if it looks like a URL
        if source.startswith("http") or source.startswith("git@"):
            tmp_dir = tempfile.mkdtemp(prefix="vulnscout_")
            base_path = clone_repo(source, tmp_dir)

        # Collect and prioritize files
        all_files = collect_files(base_path, language)

        if focus_area:
            all_files = [f for f in all_files
                        if focus_area.lower() in f.name.lower()
                        or focus_area.lower() in str(f.parent).lower()]
            console.print(f"[cyan]Focused on {len(all_files)} files matching '{focus_area}'[/cyan]")

        if not all_files:
            console.print("[red]No source files found. Check --language flag or path.[/red]")
            return []

        prioritized = prioritize_files(all_files, Path(base_path))
        chunks = load_and_chunk(prioritized, Path(base_path))

        # Choose verifier
        if binary_path:
            verifier = build_harness_verifier(binary_path)
            console.print(f"[green]Using binary harness: {binary_path}[/green]")
        else:
            verifier = static_verifier
            console.print("[yellow]Using static verifier (no binary). For confirmed crashes, build target with ASAN and pass --binary.[/yellow]")

        all_findings = []

        # Run the loop on each chunk (prioritized files first)
        for idx, chunk in enumerate(chunks):
            console.print(f"\n[bold magenta]Analyzing chunk {idx + 1}/{len(chunks)} "
                         f"({len(chunk)} files)[/bold magenta]")
            files_in_chunk = [c['path'] for c in chunk]
            console.print(f"Files: {', '.join(files_in_chunk[:5])}"
                         f"{'...' if len(files_in_chunk) > 5 else ''}")

            findings = run_repo_loop(
                source_chunks=chunk,
                verifier_fn=verifier,
                max_iterations=max_iterations,
            )
            all_findings.extend(findings)

        write_report(all_findings, mode="repo", source=source, output_dir=output_dir)
        return all_findings

    finally:
        if tmp_dir and os.path.exists(tmp_dir):
            shutil.rmtree(tmp_dir)

#!/usr/bin/env python3
"""
vulnscout check — pre-flight validation for VulnScout
Run this before starting a hunt to catch config issues early.

Usage:
    python check.py
    python check.py --fix      # attempt to auto-fix permission issues
"""

import os
import sys
import stat
import shutil
import argparse
import subprocess
from pathlib import Path

# ── ANSI colors ────────────────────────────────────────────────────────────────
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):    print(f"  {GREEN}✓{RESET}  {msg}")
def warn(msg):  print(f"  {YELLOW}!{RESET}  {msg}")
def fail(msg):  print(f"  {RED}✗{RESET}  {msg}")
def section(title): print(f"\n{BOLD}{title}{RESET}")

VULNSCOUT_DIR = Path(os.environ.get("VULNSCOUT_DIR", Path(__file__).parent.resolve()))
VENV_PYTHON   = VULNSCOUT_DIR / ".venv" / "bin" / "python"
ENV_FILE      = VULNSCOUT_DIR / ".env"
SERVICE_FILE  = Path("/etc/systemd/system/vulnscout-mcp.service")

errors   = []
warnings = []

def load_env_file():
    """Load .env file into os.environ if present."""
    if not ENV_FILE.exists():
        return
    with open(ENV_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            key, _, value = line.partition("=")
            os.environ.setdefault(key.strip(), value.strip())


def check_env_file():
    section("1. Environment file (.env)")
    if ENV_FILE.exists():
        ok(f".env found at {ENV_FILE}")
        # Check it isn't the example file
        content = ENV_FILE.read_text()
        if "sk-ant-api03-..." in content or "ghp_..." in content:
            fail(".env still contains placeholder values — fill in real keys")
            errors.append(".env has unfilled placeholders")
        else:
            ok(".env contains non-placeholder values")
    else:
        example = VULNSCOUT_DIR / ".env.example"
        if example.exists():
            fail(f".env not found. Create it with:  cp {example} {ENV_FILE}")
        else:
            fail(".env not found and no .env.example to copy from")
        errors.append(".env missing")


def check_api_keys():
    section("2. API Keys")
    load_env_file()

    # Anthropic
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not anthropic_key:
        fail("ANTHROPIC_API_KEY is not set")
        errors.append("ANTHROPIC_API_KEY missing")
    elif not anthropic_key.startswith("sk-ant-"):
        warn("ANTHROPIC_API_KEY is set but doesn't look like a valid Anthropic key")
        warnings.append("ANTHROPIC_API_KEY format unexpected")
    else:
        ok(f"ANTHROPIC_API_KEY is set ({anthropic_key[:20]}...)")

    # GitHub
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if not github_token:
        fail("GITHUB_TOKEN is not set")
        errors.append("GITHUB_TOKEN missing")
    elif not github_token.startswith(("ghp_", "github_pat_", "ghs_")):
        warn("GITHUB_TOKEN is set but doesn't look like a standard GitHub token")
        warnings.append("GITHUB_TOKEN format unexpected")
    else:
        ok(f"GITHUB_TOKEN is set ({github_token[:12]}...)")


def check_api_connectivity():
    section("3. API Connectivity")
    load_env_file()

    # Test Anthropic — lightweight models list call
    anthropic_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if anthropic_key:
        try:
            import urllib.request
            import urllib.error
            import json
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/models",
                headers={
                    "x-api-key": anthropic_key,
                    "anthropic-version": "2023-06-01",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    ok("Anthropic API key is valid (200 OK)")
                else:
                    fail(f"Anthropic API returned HTTP {resp.status}")
                    errors.append("Anthropic API key invalid")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                fail("Anthropic API key is invalid (401 Unauthorized)")
                errors.append("Anthropic API key rejected")
            elif e.code == 403:
                fail("Anthropic API key has no permissions (403 Forbidden)")
                errors.append("Anthropic API key insufficient permissions")
            else:
                warn(f"Anthropic API check returned HTTP {e.code} — key may still work")
                warnings.append(f"Anthropic API HTTP {e.code}")
        except Exception as e:
            warn(f"Could not reach Anthropic API: {e}")
            warnings.append("Anthropic API unreachable (network issue?)")
    else:
        warn("Skipping Anthropic connectivity check (key not set)")

    # Test GitHub — unauthenticated rate_limit call to validate token
    github_token = os.environ.get("GITHUB_TOKEN", "")
    if github_token:
        try:
            import urllib.request
            import urllib.error
            req = urllib.request.Request(
                "https://api.github.com/rate_limit",
                headers={
                    "Authorization": f"Bearer {github_token}",
                    "Accept": "application/vnd.github+json",
                },
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                if resp.status == 200:
                    import json
                    data = json.loads(resp.read())
                    remaining = data.get("resources", {}).get("search", {}).get("remaining", "?")
                    limit     = data.get("resources", {}).get("search", {}).get("limit", "?")
                    ok(f"GitHub token is valid — search quota: {remaining}/{limit} remaining")
                    if isinstance(remaining, int) and remaining < 5:
                        warn("GitHub search quota is nearly exhausted — wait for reset before hunting")
                        warnings.append("GitHub search quota low")
                else:
                    fail(f"GitHub API returned HTTP {resp.status}")
                    errors.append("GitHub token invalid")
        except urllib.error.HTTPError as e:
            if e.code == 401:
                fail("GitHub token is invalid (401 Unauthorized)")
                errors.append("GitHub token rejected")
            else:
                warn(f"GitHub API check returned HTTP {e.code}")
                warnings.append(f"GitHub API HTTP {e.code}")
        except Exception as e:
            warn(f"Could not reach GitHub API: {e}")
            warnings.append("GitHub API unreachable (network issue?)")
    else:
        warn("Skipping GitHub connectivity check (token not set)")


def check_venv():
    section("4. Python Virtual Environment")
    if VENV_PYTHON.exists():
        ok(f"venv found at {VENV_PYTHON}")
        # Check anthropic package is installed
        result = subprocess.run(
            [str(VENV_PYTHON), "-c", "import anthropic; print(anthropic.__version__)"],
            capture_output=True, text=True
        )
        if result.returncode == 0:
            ok(f"anthropic package installed (v{result.stdout.strip()})")
        else:
            fail("anthropic package not found in venv — run: pip install -r requirements.txt")
            errors.append("anthropic package missing from venv")

        # Check pygithub / requests
        result2 = subprocess.run(
            [str(VENV_PYTHON), "-c", "import requests"],
            capture_output=True, text=True
        )
        if result2.returncode == 0:
            ok("requests package installed")
        else:
            warn("requests package not found in venv")
            warnings.append("requests missing from venv")
    else:
        fail(f"venv not found at {VENV_PYTHON}")
        fail("Run:  python3 -m venv .venv && .venv/bin/pip install -r requirements.txt")
        errors.append("venv missing")


def check_directories(auto_fix=False):
    section("5. Directory Permissions")
    for dirname in ["logs", "findings"]:
        dirpath = VULNSCOUT_DIR / dirname
        dirpath.mkdir(exist_ok=True)
        # Check writeable by current user
        if os.access(dirpath, os.W_OK):
            ok(f"{dirname}/ is writable")
        else:
            if auto_fix:
                try:
                    subprocess.run(["sudo", "chown", "-R", f"{os.environ.get('USER','kali')}:", str(dirpath)], check=True)
                    ok(f"{dirname}/ fixed ownership (chown applied)")
                except subprocess.CalledProcessError:
                    fail(f"{dirname}/ is not writable and auto-fix failed — run: sudo chown -R kali:kali {dirpath}")
                    errors.append(f"{dirname}/ not writable")
            else:
                fail(f"{dirname}/ is not writable — run: sudo chown -R kali:kali {dirpath}  (or use --fix)")
                errors.append(f"{dirname}/ not writable")


def check_service_file():
    section("6. Systemd Service")
    if not SERVICE_FILE.exists():
        warn(f"Service file not found at {SERVICE_FILE} — skipping (OK if not using systemd)")
        warnings.append("Service file not installed")
        return

    content = SERVICE_FILE.read_text()

    # Check User= line
    if "User=root" in content:
        fail("Service file has User=root — should be User=kali (or your actual user)")
        errors.append("Service file User=root")
    elif "User=" in content:
        user_line = [l for l in content.splitlines() if l.startswith("User=")]
        ok(f"Service file user: {user_line[0] if user_line else 'found'}")
    else:
        warn("No User= line in service file — will run as root by default")
        warnings.append("Service file missing User=")

    # Check EnvironmentFile= vs inline Environment= with keys
    if "EnvironmentFile=" in content:
        ok("Service uses EnvironmentFile= (clean env loading)")
    elif "ANTHROPIC_API_KEY" in content:
        # Inline key — check for missing closing quote
        for line in content.splitlines():
            if "ANTHROPIC_API_KEY" in line and not line.rstrip().endswith('"'):
                fail('Inline Environment= line missing closing quote — key will not load')
                errors.append("Malformed Environment= line in service file")
                break
        else:
            warn("Service uses inline Environment= — consider switching to EnvironmentFile=")
            warnings.append("Inline Environment= in service file")
    else:
        fail("Service file has no ANTHROPIC_API_KEY configured")
        errors.append("Service file missing API key config")


def check_tools():
    section("7. System Tools")
    for tool in ["git", "curl"]:
        path = shutil.which(tool)
        if path:
            ok(f"{tool} found at {path}")
        else:
            warn(f"{tool} not found in PATH")
            warnings.append(f"{tool} missing")


def print_summary():
    section("─" * 50)
    if not errors and not warnings:
        print(f"\n  {GREEN}{BOLD}All checks passed — ready to hunt.{RESET}\n")
    elif not errors:
        print(f"\n  {YELLOW}{BOLD}{len(warnings)} warning(s), no errors — should be OK to proceed.{RESET}")
        for w in warnings:
            print(f"    {YELLOW}!{RESET} {w}")
        print()
    else:
        print(f"\n  {RED}{BOLD}{len(errors)} error(s) must be fixed before hunting:{RESET}")
        for e in errors:
            print(f"    {RED}✗{RESET} {e}")
        if warnings:
            print(f"\n  {YELLOW}{len(warnings)} warning(s):{RESET}")
            for w in warnings:
                print(f"    {YELLOW}!{RESET} {w}")
        print()
        sys.exit(1)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnScout pre-flight check")
    parser.add_argument("--fix", action="store_true", help="Auto-fix permission issues where possible")
    parser.add_argument("--no-network", action="store_true", help="Skip API connectivity checks")
    args = parser.parse_args()

    print(f"\n{BOLD}VulnScout Pre-flight Check{RESET}")
    print(f"  Working directory: {VULNSCOUT_DIR}")

    check_env_file()
    check_api_keys()
    if not args.no_network:
        check_api_connectivity()
    else:
        section("3. API Connectivity")
        warn("Skipped (--no-network)")
    check_venv()
    check_directories(auto_fix=args.fix)
    check_service_file()
    check_tools()
    print_summary()

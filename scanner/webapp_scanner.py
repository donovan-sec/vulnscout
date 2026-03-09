"""
Web app scanner: crawls a target URL, builds context for Claude,
runs the agentic loop, and verifies findings with real HTTP requests.
"""

import re
import time
import json
from urllib.parse import urljoin, urlparse, urlencode
from collections import defaultdict

import requests
from bs4 import BeautifulSoup
from rich.console import Console
from rich.progress import track

console = Console()

# Max pages to crawl before stopping
MAX_PAGES = 100
# Request timeout
TIMEOUT = 10
# Polite delay between requests
CRAWL_DELAY = 0.5


class Crawler:
    def __init__(self, base_url, session=None, headers=None, cookies=None):
        self.base_url = base_url.rstrip("/")
        self.base_domain = urlparse(base_url).netloc
        self.visited = set()
        self.endpoints = []
        self.js_sources = []
        self.sample_responses = {}
        self.observed_headers = {}

        self.session = session or requests.Session()
        if headers:
            self.session.headers.update(headers)
        if cookies:
            self.session.cookies.update(cookies)

        # Default headers to look like a real browser
        self.session.headers.setdefault(
            "User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/120.0.0.0 Safari/537.36"
        )

    def is_in_scope(self, url):
        parsed = urlparse(url)
        return parsed.netloc == self.base_domain

    def crawl(self, max_pages=MAX_PAGES):
        """BFS crawl of the target application."""
        queue = [self.base_url]

        with console.status("[cyan]Crawling...[/cyan]") as status:
            while queue and len(self.visited) < max_pages:
                url = queue.pop(0)
                if url in self.visited:
                    continue

                self.visited.add(url)
                status.update(f"[cyan]Crawling {len(self.visited)}/{max_pages}: {url[:60]}[/cyan]")

                try:
                    resp = self.session.get(url, timeout=TIMEOUT, allow_redirects=True)
                    time.sleep(CRAWL_DELAY)
                except Exception as e:
                    console.print(f"[red]Request failed: {url} -- {e}[/red]")
                    continue

                # Record endpoint
                self.record_endpoint("GET", url, resp)

                content_type = resp.headers.get("Content-Type", "")
                if "html" in content_type:
                    new_links = self.extract_links(url, resp.text)
                    queue.extend([l for l in new_links if l not in self.visited])
                    self.extract_forms(url, resp.text)
                    js_links = self.extract_js_links(url, resp.text)
                    for js_url in js_links[:5]:  # limit JS fetching
                        self.fetch_js(js_url)
                elif "javascript" in content_type:
                    self.js_sources.append({"url": url, "content": resp.text[:5000]})

        console.print(f"[green]Crawl complete: {len(self.visited)} pages, "
                     f"{len(self.endpoints)} endpoints[/green]")

    def record_endpoint(self, method, url, response):
        parsed = urlparse(url)
        params = dict(pair.split("=", 1) if "=" in pair else (pair, "")
                     for pair in parsed.query.split("&") if pair)

        entry = {
            "method": method,
            "url": url,
            "path": parsed.path,
            "params": params,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", ""),
            "response_size": len(response.content),
        }
        self.endpoints.append(entry)

        # Store sample response for interesting endpoints
        if parsed.query or response.status_code in (200, 302, 401, 403):
            self.sample_responses[url] = {
                "status": response.status_code,
                "headers": dict(response.headers),
                "body_snippet": response.text[:1000],
            }

        # Observe security-relevant headers
        for h in ["Server", "X-Powered-By", "X-Frame-Options", "Content-Security-Policy",
                  "Strict-Transport-Security", "Set-Cookie"]:
            if h in response.headers:
                self.observed_headers[h] = response.headers[h]

    def extract_links(self, base, html):
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("a", href=True):
            href = tag["href"]
            full_url = urljoin(base, href).split("#")[0].split("?")[0]
            if self.is_in_scope(full_url) and full_url not in self.visited:
                links.append(full_url)
        return links

    def extract_forms(self, base, html):
        """Extract form actions and parameters as endpoints."""
        soup = BeautifulSoup(html, "html.parser")
        for form in soup.find_all("form"):
            action = form.get("action", base)
            method = form.get("method", "GET").upper()
            full_url = urljoin(base, action)

            inputs = {}
            for inp in form.find_all(["input", "select", "textarea"]):
                name = inp.get("name")
                if name:
                    inputs[name] = inp.get("value", inp.get("type", "text"))

            self.endpoints.append({
                "method": method,
                "url": full_url,
                "path": urlparse(full_url).path,
                "params": inputs,
                "is_form": True,
                "status_code": None,
                "content_type": "form",
                "response_size": 0,
            })

    def extract_js_links(self, base, html):
        soup = BeautifulSoup(html, "html.parser")
        links = []
        for tag in soup.find_all("script", src=True):
            src = urljoin(base, tag["src"])
            if self.is_in_scope(src):
                links.append(src)
        return links

    def fetch_js(self, url):
        try:
            resp = self.session.get(url, timeout=TIMEOUT)
            time.sleep(CRAWL_DELAY)
            # Extract interesting JS patterns
            content = resp.text
            apis = re.findall(r'(?:fetch|axios|xhr)\s*\(\s*["\']([^"\']+)["\']', content)
            endpoints_in_js = re.findall(r'["\']/(api|v\d+|rest)/[^"\'<>]+["\']', content)
            self.js_sources.append({
                "url": url,
                "api_calls": apis[:20],
                "endpoint_hints": list(set(endpoints_in_js))[:20],
                "content": content[:3000],
            })
        except Exception:
            pass

    def build_context(self):
        """Build a structured context dict for the Claude loop."""
        # Summarize endpoints
        endpoint_lines = []
        seen_paths = set()
        for ep in self.endpoints:
            path_key = f"{ep['method']} {ep['path']}"
            if path_key not in seen_paths:
                seen_paths.add(path_key)
                params_str = ", ".join(ep.get("params", {}).keys())
                line = f"  {ep['method']} {ep['url']}"
                if params_str:
                    line += f"  [params: {params_str}]"
                endpoint_lines.append(line)

        # Sample responses
        sample_lines = []
        for url, data in list(self.sample_responses.items())[:10]:
            sample_lines.append(
                f"  {data['status']} {url}\n"
                f"    Body snippet: {data['body_snippet'][:200]}"
            )

        # JS hints
        js_lines = []
        for js in self.js_sources[:5]:
            if js.get("api_calls"):
                js_lines.append(f"  API calls found: {js['api_calls']}")
            if js.get("endpoint_hints"):
                js_lines.append(f"  Endpoint hints: {js['endpoint_hints']}")

        return {
            "base_url": self.base_url,
            "endpoints": self.endpoints,
            "sample_data": "\n".join(sample_lines) if sample_lines else "None captured",
            "js_summary": "\n".join(js_lines) if js_lines else "None",
            "headers_summary": json.dumps(self.observed_headers, indent=2),
        }


def http_verifier(session, base_url):
    """
    Returns a verifier function that executes HTTP test requests
    and checks for vulnerability indicators.
    """
    def verifier(test_request_dict):
        url = test_request_dict.get("url", "")
        method = test_request_dict.get("method", "GET")
        headers = test_request_dict.get("headers", {})
        body = test_request_dict.get("body")

        # Make URL absolute if relative
        if url and not url.startswith("http"):
            url = urljoin(base_url, url)

        if not url:
            return False, "No URL in test request"

        try:
            kwargs = {
                "headers": headers,
                "timeout": TIMEOUT,
                "allow_redirects": False,
            }

            if body:
                content_type = headers.get("Content-Type", "")
                if "json" in content_type:
                    try:
                        kwargs["json"] = json.loads(body)
                    except Exception:
                        kwargs["data"] = body
                else:
                    kwargs["data"] = body

            resp = getattr(session, method.lower())(url, **kwargs)

            details = (
                f"Status: {resp.status_code}\n"
                f"Headers: {dict(resp.headers)}\n"
                f"Body (first 1000 chars):\n{resp.text[:1000]}"
            )

            # Heuristics for likely vulnerability indicators
            confirmed = (
                # Unexpected success on protected resource
                (resp.status_code == 200 and "unauthorized" not in resp.text.lower())
                # Error messages that leak info
                or any(kw in resp.text.lower() for kw in [
                    "sql syntax", "mysql_fetch", "ora-", "syntax error",
                    "traceback", "exception", "stack trace",
                    "root:", "/etc/passwd", "uid=",
                ])
                # Auth bypass indicators
                or (resp.status_code in (200, 302) and
                    any(kw in resp.text.lower() for kw in [
                        "welcome", "dashboard", "admin", "logged in"
                    ]))
            )

            return confirmed, details

        except Exception as e:
            return False, f"Request error: {e}"

    return verifier


def scan_webapp(url, cookies=None, headers=None, auth_token=None,
                max_pages=MAX_PAGES, max_iterations=15, output_dir=None):
    """
    Main entry point for web app scanning.
    
    url: target base URL
    cookies: dict of cookies (use for authenticated scanning)
    headers: dict of custom headers
    auth_token: bearer token (added as Authorization header)
    max_pages: crawl depth limit
    max_iterations: Claude loop iterations
    """
    from scanner.claude_loop import run_webapp_loop
    from scanner.reporter import write_report

    # Set up session
    session = requests.Session()
    if headers:
        session.headers.update(headers)
    if cookies:
        session.cookies.update(cookies)
    if auth_token:
        session.headers["Authorization"] = f"Bearer {auth_token}"

    # Crawl
    crawler = Crawler(url, session=session)
    crawler.crawl(max_pages=max_pages)
    app_context = crawler.build_context()

    if not app_context["endpoints"]:
        console.print("[red]No endpoints discovered. Check the URL and try again.[/red]")
        return []

    # Build verifier
    verifier = http_verifier(session, url)

    # Run Claude loop
    findings = run_webapp_loop(
        app_context=app_context,
        verifier_fn=verifier,
        max_iterations=max_iterations,
    )

    write_report(findings, mode="webapp", source=url, output_dir=output_dir)
    return findings

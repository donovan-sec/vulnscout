# VulnScout

AI-powered vulnerability scanner using Claude in an agentic loop. Two modes:
- **Repo mode** -- clone a git repo or point at local source, static analysis + optional crash verification
- **Webapp mode** -- crawl a web app, Claude generates HTTP test cases, verifier runs them live

This is the same methodology Anthropic used to find 22 CVEs in Firefox: Claude reasons about code paths and generates targeted test inputs, a verifier confirms them, results feed back to Claude for deeper analysis.

---

## Setup

```bash
git clone <this repo>
cd vulnscout
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...
```

---

## Usage

### Repo scanning

```bash
# Scan a public repo (static analysis, no binary needed)
python main.py repo https://github.com/nicowillis/libpng

# Scan with language filter
python main.py repo https://github.com/org/project --language python

# Focus on a specific subsystem
python main.py repo https://github.com/org/project --focus auth

# Scan local directory
python main.py repo ./path/to/source --language c_cpp

# With binary harness for crash confirmation (see below)
python main.py repo https://github.com/org/project --binary ./target_asan
```

### Web app scanning

```bash
# Unauthenticated scan
python main.py webapp https://target.example.com

# Authenticated with bearer token
python main.py webapp https://api.example.com --auth-token eyJhbGci...

# Authenticated with session cookie (grab from browser devtools → Network → copy cookie header)
python main.py webapp https://app.example.com --cookie "session=abc123; csrf=xyz789"

# With custom headers
python main.py webapp https://app.example.com -H "X-Api-Key: key123" -H "X-Tenant: acme"

# Limit crawl depth (faster, less coverage)
python main.py webapp https://app.example.com --max-pages 30 --iterations 10
```

---

## Hard crash verification (repo mode)

Static mode trusts Claude's analysis but can't confirm crashes. For memory-unsafe languages (C/C++, Rust unsafe), build with AddressSanitizer for real confirmation:

```bash
# For a C/C++ project with make
CC=clang CFLAGS="-fsanitize=address,undefined -g -O1" \
CXX=clang++ CXXFLAGS="-fsanitize=address,undefined -g -O1" \
make -j$(nproc)

# Copy the binary and pass it to vulnscout
cp ./build/your_binary ./target_asan
python main.py repo ./source --binary ./target_asan

# For CMake projects
cmake -DCMAKE_C_COMPILER=clang \
      -DCMAKE_CXX_COMPILER=clang++ \
      -DCMAKE_C_FLAGS="-fsanitize=address,undefined -g -O1" \
      -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -g -O1" \
      -B build && cmake --build build -j$(nproc)
```

The binary must accept input from stdin. If it takes a filename instead, modify `build_harness_verifier` in `scanner/repo_scanner.py` to write Claude's input to a temp file and pass that path.

---

## Understanding the output

Reports land in `./findings/` (or wherever `--output` points):

- `vulnscout_repo_<target>_<timestamp>.md` -- human-readable report with analysis, PoCs, and disclosure notes
- `vulnscout_repo_<target>_<timestamp>.json` -- structured data for further processing

**Important:** confirmed findings in static mode mean Claude produced a concrete, specific hypothesis. They still need manual validation before filing. Confirmed findings in binary/HTTP mode have been automatically verified.

---

## Tips for getting real CVEs

**Pick the right target**
- Small to mid-size C/C++ libraries with active maintenance (they'll actually assign a CVE)
- Projects with a `SECURITY.md` or published CVD policy
- Avoid browser engines and crypto libs -- too well-audited, too complex
- Good hunting grounds: image parsers, network protocol parsers, compression libs, auth libraries

**Web app targets**
- Your own apps (always fine)
- Bug bounty programs on HackerOne or Bugcrowd with defined scope
- Open source web apps you can run locally

**For IAM-specific findings**
- OAuth library implementations
- SAML parsers
- JWT validation logic
- LDAP query construction (injection)

**Filing a CVE**
1. Reproduce manually in your own environment
2. Contact the maintainer privately via their security email or security.md
3. Give them 90 days (standard coordinated disclosure window)
4. After patch ships, request CVE via https://cveform.mitre.org/ 
5. Reference the fix commit and your disclosure timeline

---

## Cost expectations

- Repo scan (static, 1-2 chunks): ~$0.50-2.00 per session with Opus
- Repo scan (large codebase, many chunks): $5-20
- Webapp scan: ~$1-5 depending on iteration count

Anthropic's Firefox work cost ~$4k but that was exploit development, not just finding. Finding is significantly cheaper.

---

## Limitations

- **Static mode** can't confirm crashes -- it records Claude's analysis but verification requires a build
- **Web app mode** uses heuristics to detect confirmed findings -- some true positives need manual review
- **Context window** limits how much code fits in one chunk -- large codebases get chunked, which means cross-file vulnerabilities may be missed
- **Rate limiting** -- if you hit API limits, add a `time.sleep()` between iterations in `claude_loop.py`
- This is a research tool, not a product. Treat output as leads to investigate, not proof

---

## Legal

Only use on targets you own or have explicit written authorization to test. 
The web scanner includes an authorization prompt that must be confirmed before scanning.

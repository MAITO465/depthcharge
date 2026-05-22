import os
import tarfile
import zipfile
import tempfile
import requests
import ast
import re
import math
import yara

# Shannon entropy calculator as specified in PFS Report Listing 1
def entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data)}
    return - sum(p * math.log2(p) for p in freq.values())

# Popular packages list to check similarity for typosquatting detection (will be loaded/cached dynamically in reputation)
POPULAR_PACKAGES = {
    "pypi": [
        "requests", "urllib3", "numpy", "pandas", "cryptography", "jinja2", "click", "boto3",
        "django", "flask", "pydantic", "pyyaml", "certifi", "six", "wheel", "setuptools",
        "pytest", "black", "isort", "pip", "virtualenv", "poetry", "ansible", "matplotlib"
    ],
    "npm": [
        "lodash", "react", "vue", "express", "chalk", "request", "async", "commander",
        "uuid", "axios", "debug", "moment", "fs-extra", "dotenv", "glob", "minimist",
        "tslib", "semver", "mkdirp", "bluebird", "webpack", "babel-core", "inquirer"
    ]
}

# Regex patterns for sensitive files and environment keys
SUSPICIOUS_STRINGS = [
    r"/etc/passwd",
    r"\b\.ssh\b",
    r"\b\.aws/credentials\b",
    r"\b\.env\b",
    r"/\.bash_history",
    r"/\.bashrc",
    r"AWS_ACCESS_KEY_ID",
    r"AWS_SECRET_ACCESS_KEY",
    r"GITHUB_TOKEN",
    r"DISCORD_WEBHOOK",
    r"SLACK_WEBHOOK",
    r"STRIPE_API_KEY",
    r"PRIVATE_KEY"
]

# Refined YARA rules to prevent false positives and avoid reserved word issues
YARA_RULES = r"""
rule python_obfuscated_eval {
    meta:
        description = "Detects python eval/exec of base64/zlib/hex decode"
    strings:
        $eval_b64 = /(eval|exec)[ \t]*\([ \t]*([a-zA-Z0-9_]+\.)*b64decode[ \t]*\(/ nocase
        $eval_zlib = /(eval|exec)[ \t]*\([ \t]*([a-zA-Z0-9_]+\.)*decompress[ \t]*\(/ nocase
        $eval_decode = /(eval|exec)[ \t]*\([ \t]*([a-zA-Z0-9_]+\.)*decode[ \t]*\(/ nocase
        $eval_hex = /(eval|exec)[ \t]*\([ \t]*(bytes\.)?fromhex[ \t]*\(/ nocase
    condition:
        any of them
}

rule js_obfuscated_eval {
    meta:
        description = "Detects JS evaluation of Buffer base64/hex conversions"
    strings:
        $eval_b64 = /(eval|Function)[ \t]*\([ \t]*Buffer\.from[ \t]*\([ \t]*[^)]+[ \t]*,[ \t]*['"]base64['"][ \t]*\)\.toString[ \t]*\([ \t]*\)[ \t]*\)/ nocase
        $eval_hex = /(eval|Function)[ \t]*\([ \t]*Buffer\.from[ \t]*\([ \t]*[^)]+[ \t]*,[ \t]*['"]hex['"][ \t]*\)\.toString[ \t]*\([ \t]*\)[ \t]*\)/ nocase
    condition:
        any of them
}

rule suspicious_exfiltration {
    meta:
        description = "Detects exfiltration URL callbacks"
    strings:
        $discord = /discord(app)?\.com\/api\/webhooks/ nocase
        $telegram = /api\.telegram\.org\/bot/ nocase
        $slack = /hooks\.slack\.com\/services/ nocase
        $webhook = /webhook\.site/ nocase
        $requestbin = /requestbin/ nocase
    condition:
        any of them
}

rule python_reverse_shell {
    meta:
        description = "Detects python reverse shell patterns"
    strings:
        $socket = "socket.socket" nocase
        $connect = ".connect(" nocase
        $subprocess = "subprocess" nocase
        $dup2 = "os.dup2" nocase
    condition:
        all of them
}

rule sensitive_files_access {
    meta:
        description = "Detects access to sensitive file paths and keys"
    strings:
        $passwd = /\/etc\/passwd\b/ nocase
        $ssh = /\b\.ssh\b/ nocase
        $aws = /\b\.aws\/credentials\b/ nocase
        $env = /\b\.env\b/ nocase
    condition:
        any of them
}
"""

compiled_yara_rules = yara.compile(source=YARA_RULES)

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
        
    return previous_row[-1]

def check_typosquatting(package_name, ecosystem):
    """
    Checks if the package name is suspiciously similar to a highly popular package.
    """
    ecosystem = ecosystem.lower()
    targets = POPULAR_PACKAGES.get(ecosystem, [])
    original_name = package_name
    package_lower = package_name.lower()
    
    # Build a case-insensitive lookup: lowered_name -> canonical_name
    targets_lower = {t.lower(): t for t in targets}
    
    if package_lower in targets_lower:
        canonical = targets_lower[package_lower]
        # If the original name differs in casing from the canonical popular package,
        # flag it as case-confusion typosquatting (e.g. requesTs vs requests)
        if original_name != canonical:
            return {
                "target": canonical,
                "distance": 0,
                "message": f"Package name '{original_name}' uses unusual casing of popular package '{canonical}'. Possible typosquatting via case confusion."
            }
        return None
        
    for target in targets:
        dist = levenshtein_distance(package_lower, target.lower())
        if 0 < dist <= 2:
            return {
                "target": target,
                "distance": dist,
                "message": f"Package name '{original_name}' is highly similar to popular package '{target}' (edit distance: {dist}). Possibility of typo-squatting."
            }
    return None

def is_decoding_node(node):
    if isinstance(node, ast.Call):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
        if any(d in func_name.lower() for d in ["b64decode", "decompress", "fromhex", "decode"]):
            return True
        return any(is_decoding_node(arg) for arg in node.args)
    elif isinstance(node, ast.BinOp):
        return is_decoding_node(node.left) or is_decoding_node(node.right)
    return False

def is_constant_concatenation(node):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
        return is_constant_concatenation(node.left) and is_constant_concatenation(node.right)
    return False

class StaticASTVisitor(ast.NodeVisitor):
    def __init__(self, filename, npm_hooks=None):
        self.filename = filename
        self.npm_hooks = npm_hooks or set()
        self.alerts = []
        self.imports = set()
        self.obfuscation_detected = False
        self.dangerous_ast_detected = False
        
    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
            file_lower = self.filename.lower()
            is_hook = (
                file_lower == "setup.py" or
                file_lower in self.npm_hooks or
                any(h in file_lower for h in ["preinstall", "postinstall"]) or
                (file_lower.startswith("install") and file_lower.endswith(".py"))
            )
            if is_hook and alias.name in ["socket", "subprocess", "requests", "urllib", "http", "pty"]:
                self.dangerous_ast_detected = True
                self.alerts.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "type": "setup_hook_danger",
                    "message": f"Install hook file imports network/process library: '{alias.name}'"
                })
        self.generic_visit(node)
        
    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module)
            file_lower = self.filename.lower()
            is_hook = (
                file_lower == "setup.py" or
                file_lower in self.npm_hooks or
                any(h in file_lower for h in ["preinstall", "postinstall"]) or
                (file_lower.startswith("install") and file_lower.endswith(".py"))
            )
            if is_hook and any(m in node.module for m in ["socket", "subprocess", "requests", "urllib", "http", "pty"]):
                self.dangerous_ast_detected = True
                self.alerts.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "type": "setup_hook_danger",
                    "message": f"Install hook file imports from network/process library: '{node.module}'"
                })
        self.generic_visit(node)
        
    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr
            
        file_lower = self.filename.lower()
        is_hook = (
            file_lower == "setup.py" or
            file_lower in self.npm_hooks or
            any(h in file_lower for h in ["preinstall", "postinstall"]) or
            (file_lower.startswith("install") and file_lower.endswith(".py"))
        )
            
        if func_name in ["eval", "exec"]:
            is_suspicious_eval = False
            if node.args:
                arg = node.args[0]
                if is_decoding_node(arg):
                    is_suspicious_eval = True
            else:
                is_suspicious_eval = True

            if is_hook or is_suspicious_eval:
                self.dangerous_ast_detected = True
                severity = "high"
            else:
                severity = "medium"

            self.alerts.append({
                "file": self.filename,
                "line": node.lineno,
                "severity": severity,
                "type": "dynamic_execution",
                "message": f"Dynamic execution '{func_name}' found (suspicious: {is_suspicious_eval or is_hook})."
            })
            
        if is_hook:
            # Spawning processes or networking inside install hooks is dangerous
            if func_name in ["system", "popen", "spawn", "run", "Popen", "call", "check_output", "connect", "get", "post", "urlopen"]:
                self.dangerous_ast_detected = True
                self.alerts.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "type": "setup_hook_danger",
                    "message": f"Install hook file executes subprocess or network call: '{func_name}'"
                })
                
        if func_name == "getattr" and len(node.args) >= 2:
            if isinstance(node.args[1], ast.BinOp) and is_constant_concatenation(node.args[1]):
                self.obfuscation_detected = True
                self.alerts.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "type": "obfuscation",
                    "message": "getattr obfuscation with concatenated attributes."
                })
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            val = node.value
            # Shannon entropy check on string literals (> 4.8 and len > 120 and whitespace < 2% suggests obfuscation)
            ent = entropy(val)
            whitespace_count = sum(1 for c in val if c.isspace())
            whitespace_ratio = whitespace_count / len(val) if val else 0
            
            if len(val) > 120 and ent > 4.8 and whitespace_ratio < 0.02:
                self.obfuscation_detected = True
                self.alerts.append({
                    "file": self.filename,
                    "line": node.lineno,
                    "severity": "high",
                    "type": "high_entropy",
                    "message": f"High-entropy string literal (len: {len(val)}, entropy: {ent:.2f}, whitespace_ratio: {whitespace_ratio:.2%})"
                })
            
            file_lower = self.filename.lower()
            is_hook = (
                file_lower == "setup.py" or
                file_lower in self.npm_hooks or
                any(h in file_lower for h in ["preinstall", "postinstall"]) or
                (file_lower.startswith("install") and file_lower.endswith(".py"))
            )
            
            for pattern in SUSPICIOUS_STRINGS:
                if re.search(pattern, val, re.IGNORECASE):
                    is_critical_path = any(p in pattern for p in ["passwd", "ssh", "credentials"])
                    
                    # Only flag dangerous AST if critical credentials path or inside setup hooks
                    if is_hook or is_critical_path:
                        self.dangerous_ast_detected = True
                        severity = "high"
                    else:
                        severity = "medium"
                        
                    self.alerts.append({
                        "file": self.filename,
                        "line": node.lineno,
                        "severity": severity,
                        "type": "sensitive_data",
                        "message": f"Sensitive pattern/file match: '{pattern}'"
                    })
        self.generic_visit(node)

def analyze_python_file(filepath, relative_path, npm_hooks=None):
    """
    Performs AST & YARA analysis on a Python file.
    """
    alerts = []
    obfuscation_detected = False
    dangerous_ast_detected = False
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
            
        # YARA matching
        try:
            matches = compiled_yara_rules.match(filepath)
            for match in matches:
                # Obfuscation rule flags obfuscation, exfiltration/shells flag dangerous AST
                if match.rule in ["python_obfuscated_eval", "js_obfuscated_eval"]:
                    obfuscation_detected = True
                elif match.rule in ["suspicious_exfiltration", "python_reverse_shell"]:
                    dangerous_ast_detected = True
                elif match.rule in ["sensitive_files_access"]:
                    file_lower = relative_path.lower()
                    is_hook = (
                        file_lower == "setup.py" or
                        (npm_hooks and file_lower in npm_hooks) or
                        any(h in file_lower for h in ["preinstall", "postinstall"]) or
                        (file_lower.startswith("install") and file_lower.endswith(".py"))
                    )
                    # Check if match has passwd or ssh to set dangerous AST, else only if in setup hooks
                    has_passwd_or_ssh = False
                    for string_match in match.strings:
                        matched_str = str(string_match[2]).lower()
                        if "passwd" in matched_str or "ssh" in matched_str or "credentials" in matched_str:
                            has_passwd_or_ssh = True
                            break
                    if is_hook or has_passwd_or_ssh:
                        dangerous_ast_detected = True
                
                alerts.append({
                    "file": relative_path,
                    "line": 1,
                    "severity": "high",
                    "type": "yara_match",
                    "message": f"YARA match: {match.rule}"
                })
        except Exception:
            pass
            
        # AST Parser
        try:
            tree = ast.parse(source, filename=filepath)
            visitor = StaticASTVisitor(relative_path, npm_hooks=npm_hooks)
            visitor.visit(tree)
            alerts.extend(visitor.alerts)
            if visitor.obfuscation_detected:
                obfuscation_detected = True
            if visitor.dangerous_ast_detected:
                dangerous_ast_detected = True
        except SyntaxError:
            alerts.append({
                "file": relative_path,
                "line": 1,
                "severity": "low",
                "type": "syntax_error",
                "message": "Unable to parse Python AST."
            })
    except Exception as e:
        alerts.append({
            "file": relative_path,
            "line": 0,
            "severity": "low",
            "type": "error",
            "message": f"Error scanning file: {e}"
        })
        
    return alerts, obfuscation_detected, dangerous_ast_detected

def analyze_generic_file(filepath, relative_path, npm_hooks=None):
    """
    Performs YARA and string scanning on JS or other ecosystem files.
    """
    alerts = []
    obfuscation_detected = False
    dangerous_ast_detected = False
    
    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()
            
        # YARA matching
        try:
            matches = compiled_yara_rules.match(filepath)
            for match in matches:
                if match.rule in ["python_obfuscated_eval", "js_obfuscated_eval"]:
                    obfuscation_detected = True
                elif match.rule in ["suspicious_exfiltration", "python_reverse_shell"]:
                    dangerous_ast_detected = True
                elif match.rule in ["sensitive_files_access"]:
                    file_lower = relative_path.lower()
                    is_hook = (
                        (npm_hooks and file_lower in npm_hooks) or
                        any(h in file_lower for h in ["preinstall", "postinstall"])
                    )
                    has_passwd_or_ssh = False
                    for string_match in match.strings:
                        matched_str = str(string_match[2]).lower()
                        if "passwd" in matched_str or "ssh" in matched_str or "credentials" in matched_str:
                            has_passwd_or_ssh = True
                            break
                    if is_hook or has_passwd_or_ssh:
                        dangerous_ast_detected = True
                
                alerts.append({
                    "file": relative_path,
                    "line": 1,
                    "severity": "high",
                    "type": "yara_match",
                    "message": f"YARA match: {match.rule}"
                })
        except Exception:
            pass

        # Check line-by-line for high-entropy strings or sensitive keywords
        lines = source.splitlines()
        file_lower = relative_path.lower()
        is_hook_file = (
            (npm_hooks and file_lower in npm_hooks) or
            any(h in file_lower for h in ["preinstall", "postinstall"])
        )
        
        for i, line in enumerate(lines, 1):
            if "child_process" in line or "exec(" in line or "spawn(" in line:
                if is_hook_file:
                    dangerous_ast_detected = True
                    severity = "high"
                else:
                    severity = "medium"
                alerts.append({
                    "file": relative_path,
                    "line": i,
                    "severity": severity,
                    "type": "process_spawn",
                    "message": f"Process execution string pattern found: '{line.strip()[:60]}'"
                })
                
            if "eval(" in line or "Function(" in line:
                # Check for dynamic script evaluation or base64 decoding
                is_suspicious_eval = "base64" in line or "hex" in line or "Buffer.from" in line
                if is_hook_file or is_suspicious_eval:
                    dangerous_ast_detected = True
                    severity = "high"
                else:
                    severity = "medium"
                alerts.append({
                    "file": relative_path,
                    "line": i,
                    "severity": severity,
                    "type": "dynamic_execution",
                    "message": f"Dynamic execution pattern found: '{line.strip()[:60]}'"
                })
                
            # Find quoted strings in JS using regex
            quoted_strings = re.findall(r"['\"`](.*?)['\"`]", line)
            for qs in quoted_strings:
                ent = entropy(qs)
                whitespace_count = sum(1 for c in qs if c.isspace())
                whitespace_ratio = whitespace_count / len(qs) if qs else 0
                if len(qs) > 120 and ent > 4.8 and whitespace_ratio < 0.02:
                    obfuscation_detected = True
                    alerts.append({
                        "file": relative_path,
                        "line": i,
                        "severity": "high",
                        "type": "high_entropy",
                        "message": f"High entropy JS string detected (len: {len(qs)}, entropy: {ent:.2f}, whitespace_ratio: {whitespace_ratio:.2%})"
                    })
                    
            for pattern in SUSPICIOUS_STRINGS:
                if re.search(pattern, line, re.IGNORECASE):
                    is_critical_path = any(p in pattern for p in ["passwd", "ssh", "credentials"])
                    if is_hook_file or is_critical_path:
                        dangerous_ast_detected = True
                        severity = "high"
                    else:
                        severity = "medium"
                    alerts.append({
                        "file": relative_path,
                        "line": i,
                        "severity": severity,
                        "type": "sensitive_data",
                        "message": f"Sensitive pattern match: '{pattern}'"
                    })
    except Exception as e:
        alerts.append({
            "file": relative_path,
            "line": 0,
            "severity": "low",
            "type": "error",
            "message": f"Error scanning file: {e}"
        })
        
    return alerts, obfuscation_detected, dangerous_ast_detected

def get_npm_install_hooks(directory_path):
    hook_files = set()
    package_json_path = os.path.join(directory_path, "package.json")
    if not os.path.exists(package_json_path):
        # Look one level down in case of nested root
        for root, dirs, files in os.walk(directory_path):
            if "package.json" in files:
                package_json_path = os.path.join(root, "package.json")
                break
                
    if os.path.exists(package_json_path):
        try:
            with open(package_json_path, "r", encoding="utf-8", errors="ignore") as f:
                import json
                data = json.load(f)
                scripts = data.get("scripts", {})
                for hook in ["preinstall", "postinstall", "install"]:
                    cmd = scripts.get(hook, "")
                    if cmd:
                        # Extract potential JS/shell script file names from the command
                        for word in cmd.split():
                            word_clean = word.strip("`'\"&|;()").strip()
                            if word_clean.endswith(".js") or word_clean.endswith(".sh"):
                                hook_files.add(os.path.basename(word_clean).lower())
        except Exception:
            pass
    return hook_files

def scan_directory(directory_path):
    """
    Scans an extracted package directory.
    """
    alerts = []
    files_scanned = 0
    obfuscation_detected = False
    dangerous_ast_detected = False
    
    npm_hooks = get_npm_install_hooks(directory_path)
    ALLOWED_EXTENSIONS = {
        ".py", ".pyw",
        ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".sh", ".bash", ".bat", ".cmd"
    }
    
    for root, dirs, files in os.walk(directory_path):
        for file in files:
            filepath = os.path.join(root, file)
            relpath = os.path.relpath(filepath, directory_path)
            
            parts = relpath.lower().split(os.sep)
            # Skip documentation, tests, benchmarks, github workflows, environments, virtualenvs, etc.
            skip_dirs = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "benchmark", ".github", ".git", ".tox", "venv", ".venv", "htmlcov"}
            if any(p in skip_dirs for p in parts):
                continue
                
            file_lower = file.lower()
            if file_lower.startswith("test_") or file_lower.endswith("_test.py") or file_lower == "conftest.py":
                continue
                
            ext = os.path.splitext(file)[1].lower()
            if ext not in ALLOWED_EXTENSIONS and file_lower not in ["setup.py", "package.json"]:
                continue
                
            files_scanned += 1
            if ext == ".py":
                file_alerts, obf, ast_dang = analyze_python_file(filepath, relpath, npm_hooks=npm_hooks)
            else:
                file_alerts, obf, ast_dang = analyze_generic_file(filepath, relpath, npm_hooks=npm_hooks)
                
            alerts.extend(file_alerts)
            if obf:
                obfuscation_detected = True
            if ast_dang:
                dangerous_ast_detected = True
                
    return alerts, files_scanned, obfuscation_detected, dangerous_ast_detected

def scan_static(package_name, ecosystem, download_url=None):
    """
    Performs complete static analysis.
    """
    results = {
        "typosquatting": None,
        "alerts": [],
        "files_scanned": 0,
        "obfuscation_detected": False,
        "dangerous_ast_detected": False,
        "success": False,
        "error": None
    }
    
    # 1. Typo-squatting detection
    typo = check_typosquatting(package_name, ecosystem)
    if typo:
        results["typosquatting"] = typo
        results["alerts"].append({
            "file": "package_name",
            "line": 0,
            "severity": "high",
            "type": "typosquatting",
            "message": typo["message"]
        })
        
    if not download_url:
        results["error"] = "No download URL available to fetch package contents."
        return results

    # 2. Download and Scan package contents
    try:
        temp_dir = tempfile.mkdtemp(prefix="depthcharge_")
        
        file_ext = ".tar.gz"
        if ".tar.gz" in download_url or download_url.endswith(".tgz"):
            file_ext = ".tar.gz"
        elif download_url.endswith(".zip"):
            file_ext = ".zip"
            
        archive_path = os.path.join(temp_dir, f"package{file_ext}")
        
        if download_url.startswith("file://"):
            local_path = download_url[7:]
            import shutil
            shutil.copy(local_path, archive_path)
        else:
            response = requests.get(download_url, stream=True, timeout=20)
            if response.status_code != 200:
                results["error"] = f"Failed to download package archive from {download_url} (HTTP {response.status_code})"
                return results
                
            with open(archive_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)
                
        extract_path = os.path.join(temp_dir, "extracted")
        os.makedirs(extract_path, exist_ok=True)
        
        if file_ext == ".tar.gz":
            try:
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(path=extract_path)
            except Exception:
                with tarfile.open(archive_path, "r") as tar:
                    tar.extractall(path=extract_path)
        elif file_ext == ".zip":
            with zipfile.ZipFile(archive_path, 'r') as zip_ref:
                zip_ref.extractall(extract_path)
                
        alerts, files_scanned, obf, ast_dang = scan_directory(extract_path)
        results["alerts"].extend(alerts)
        results["files_scanned"] = files_scanned
        results["obfuscation_detected"] = obf
        results["dangerous_ast_detected"] = ast_dang
        results["success"] = True
        
        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    except Exception as e:
        results["error"] = f"Error during static scan download/extraction: {e}"
        
    return results

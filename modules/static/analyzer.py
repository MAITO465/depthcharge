import os
import tarfile
import zipfile
import tempfile
import requests
import ast
import re
import math
import yara

# ── Shannon entropy ──────────────────────────────────────────────────────────
def entropy(data: str) -> float:
    if not data:
        return 0.0
    freq = {c: data.count(c) / len(data) for c in set(data)}
    return -sum(p * math.log2(p) for p in freq.values())


# ── Popular package list (typosquatting seed) ─────────────────────────────────
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

# ── False-positive suppression whitelist ─────────────────────────────────────
# Entries: (pattern_substring, package_name) — suppress that pattern for that package
FP_WHITELIST = {
    ("AWS_ACCESS_KEY_ID", "awscli"),
    ("AWS_ACCESS_KEY_ID", "awscli-login"),
    ("AWS_SECRET_ACCESS_KEY", "awscli"),
    ("AWS_SECRET_ACCESS_KEY", "awscli-login"),
    ("AWS_ACCESS_KEY_ID", "boto3"),
    ("AWS_SECRET_ACCESS_KEY", "boto3"),
    ("GITHUB_TOKEN", "actions-toolkit"),
    ("STRIPE_API_KEY", "stripe"),
}

# ── MITRE ATT&CK mapping ─────────────────────────────────────────────────────
# finding_type → (technique_id, technique_name, compliance_controls)
MITRE_MAPPING = {
    "dynamic_execution":    ("T1059",     "Command and Scripting Interpreter",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21", "DORA: Art.6"]),
    "setup_hook_danger":    ("T1195.001", "Compromise Software Dependencies and Development Tools",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21", "DORA: Art.5"]),
    "obfuscation":          ("T1027",     "Obfuscated Files or Information",
                             ["NIST SP 800-161: SA-11", "NIS2: Art.21"]),
    "high_entropy":         ("T1027",     "Obfuscated Files or Information",
                             ["NIST SP 800-161: SA-11", "NIS2: Art.21"]),
    "yara_match":           ("T1195.001", "Compromise Software Dependencies and Development Tools",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21"]),
    "sensitive_data":       ("T1552",     "Unsecured Credentials",
                             ["NIST SP 800-161: IA-5", "NIS2: Art.21", "DORA: Art.9"]),
    "process_spawn":        ("T1059",     "Command and Scripting Interpreter",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21"]),
    "typosquatting":        ("T1195.001", "Compromise Software Dependencies and Development Tools",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21"]),
    "ioc_match":            ("T1071",     "Application Layer Protocol",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21", "DORA: Art.6"]),
    "taint_flow":           ("T1059",     "Command and Scripting Interpreter",
                             ["NIST SP 800-161: SA-12", "NIS2: Art.21"]),
    "chr_obfuscation":      ("T1027",     "Obfuscated Files or Information",
                             ["NIST SP 800-161: SA-11", "NIS2: Art.21"]),
    "string_split_obfusc":  ("T1027",     "Obfuscated Files or Information",
                             ["NIST SP 800-161: SA-11", "NIS2: Art.21"]),
}

# Known C2 / exfil domains used in real supply-chain campaigns.
# Only include patterns specific enough to have a near-zero false-positive rate.
# NOTE: hex-encoded IPv4 literals (0x[0-9a-fA-F]{8}) were intentionally removed —
# they match every network/crypto constant in legitimate packages (scapy, pandas,
# cryptography). The YARA rules cover real C2 indicators (Telegram tokens, Discord
# tokens, webhook URLs) with much higher precision.
IOC_DOMAINS = [
    r"requestb\.in",
    r"pipedream\.net",
    r"webhook\.site",
    r"burpcollaborator\.net",
    r"interact\.sh",
    r"canarytokens\.com",
    r"\bngrok\.io\b",
]

# ── JS dynamic-execution word-boundary pattern ───────────────────────────────
# Matches eval( or Function( only when not preceded by an identifier character,
# preventing false positives from isFunction(), assertIsFunction(), etc.
JS_EVAL_PAT = re.compile(r'(?<![a-zA-Z0-9_$])(eval|Function)\s*\(')

# ── Build-tool / infrastructure file classifier ───────────────────────────────
# Files in these path segments are legitimate build infrastructure.
# Taint flows and env_var_exfil hits here are expected (PKG_CONFIG → subprocess,
# proxy env vars → network calls) and should not set dangerous_ast_detected.
_BUILD_TOOL_SEGS = frozenset([
    "distutils", "build_ext", "build_tools", "build_scripts", "build_clib",
    "build_src", "build_py", "setuptools", "wheel", "wheels", "compiler",
    "_build", "scons", "waf", "_vendored", "vendor", "vendored",
])

def _is_build_tool_file(relative_path: str) -> bool:
    """Return True if the file lives inside a known build-infrastructure directory."""
    parts = frozenset(relative_path.lower().replace("\\", "/").split("/"))
    return bool(parts & _BUILD_TOOL_SEGS)


# ── Regex patterns for sensitive files and environment keys
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

# ── YARA rules ────────────────────────────────────────────────────────────────
YARA_RULES = r"""
rule python_obfuscated_eval {
    meta:
        description = "Detects python eval/exec of base64/zlib/hex decode"
        mitre = "T1027"
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
        mitre = "T1027"
    strings:
        $eval_b64 = /(eval|Function)[ \t]*\([ \t]*Buffer\.from[ \t]*\([ \t]*[^)]+[ \t]*,[ \t]*['"]base64['"][ \t]*\)\.toString[ \t]*\([ \t]*\)[ \t]*\)/ nocase
        $eval_hex = /(eval|Function)[ \t]*\([ \t]*Buffer\.from[ \t]*\([ \t]*[^)]+[ \t]*,[ \t]*['"]hex['"][ \t]*\)\.toString[ \t]*\([ \t]*\)[ \t]*\)/ nocase
    condition:
        any of them
}

rule suspicious_exfiltration {
    meta:
        description = "Detects exfiltration URL callbacks"
        mitre = "T1071"
    strings:
        $discord = /discord(app)?\.com\/api\/webhooks/ nocase
        $telegram = /api\.telegram\.org\/bot/ nocase
        $slack = /hooks\.slack\.com\/services/ nocase
        $webhook = /webhook\.site/ nocase
        $requestbin = /requestbin/ nocase
        $pipedream = /pipedream\.net/ nocase
        $interact = /interact\.sh/ nocase
        $ngrok = /ngrok\.io/ nocase
    condition:
        any of them
}

rule telegram_bot_token {
    meta:
        description = "Detects hardcoded Telegram bot API tokens"
        mitre = "T1071"
    strings:
        $token = /[0-9]{8,10}:[A-Za-z0-9_\-]{35}/ nocase
    condition:
        $token
}

rule discord_bot_token {
    meta:
        description = "Detects Discord bot tokens (hardcoded)"
        mitre = "T1071"
    strings:
        $token = /[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}/ nocase
    condition:
        $token
}

rule python_reverse_shell {
    meta:
        description = "Detects python reverse shell patterns"
        mitre = "T1059"
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
        mitre = "T1552"
    strings:
        $passwd = /\/etc\/passwd\b/ nocase
        $ssh = /\b\.ssh\b/ nocase
        $aws = /\b\.aws\/credentials\b/ nocase
        $env = /\b\.env\b/ nocase
    condition:
        any of them
}

rule chr_array_obfuscation {
    meta:
        description = "Detects chr()-based string reconstruction used to hide function names"
        mitre = "T1027"
    strings:
        $chr_chain = /chr\([0-9]+\)\s*\+\s*chr\([0-9]+\)/ nocase
    condition:
        $chr_chain
}

rule env_var_exfil {
    meta:
        description = "Detects reading of environment variables followed by network ops — credential theft pattern"
        mitre = "T1552"
    strings:
        $env_read = /os\.environ/ nocase
        $net_op   = /(requests\.(get|post)|urllib\.request|http\.client|socket\.connect)/ nocase
    condition:
        $env_read and $net_op
}
"""

compiled_yara_rules = yara.compile(source=YARA_RULES)

# ── YARA rule → finding type map ─────────────────────────────────────────────
YARA_RULE_TYPE = {
    "python_obfuscated_eval": "obfuscation",
    "js_obfuscated_eval": "obfuscation",
    "suspicious_exfiltration": "ioc_match",
    "telegram_bot_token": "ioc_match",
    "discord_bot_token": "ioc_match",
    "python_reverse_shell": "setup_hook_danger",
    "sensitive_files_access": "sensitive_data",
    "chr_array_obfuscation": "chr_obfuscation",
    "env_var_exfil": "sensitive_data",
}


# ── Typosquatting ─────────────────────────────────────────────────────────────
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
    ecosystem = ecosystem.lower()
    targets = POPULAR_PACKAGES.get(ecosystem, [])
    original_name = package_name
    package_lower = package_name.lower()
    targets_lower = {t.lower(): t for t in targets}

    if package_lower in targets_lower:
        canonical = targets_lower[package_lower]
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


# ── AST helpers ───────────────────────────────────────────────────────────────
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


def _is_chr_call(node):
    """Return True if node is chr(<constant>)."""
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "chr"
        and len(node.args) == 1
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, int)
    )


def _extract_chr_string(node):
    """
    Try to reconstruct the string built by chained chr() + chr() concatenation.
    Returns the decoded string on success, None otherwise.
    """
    chars = []
    def _collect(n):
        if _is_chr_call(n):
            chars.append(chr(n.args[0].value))
            return True
        if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
            return _collect(n.left) and _collect(n.right)
        return False
    if _collect(node):
        return "".join(chars)
    return None


# ── Finding builder ───────────────────────────────────────────────────────────
def make_finding(filename, line, severity, ftype, message, confidence, package_name=None):
    """
    Creates a normalised finding dict with MITRE ATT&CK tags and confidence.
    Applies FP suppression: returns None if this (pattern, package) is whitelisted.
    """
    # False-positive suppression
    if package_name:
        for (pat_substr, pkg_name) in FP_WHITELIST:
            if pkg_name == package_name and pat_substr in message:
                return None

    mitre = MITRE_MAPPING.get(ftype, ("T0000", "Unknown", []))
    return {
        "file": filename,
        "line": line,
        "severity": severity,
        "type": ftype,
        "message": message,
        "confidence": confidence,          # "high" | "medium" | "low"
        "mitre_id": mitre[0],
        "mitre_technique": mitre[1],
        "compliance": mitre[2],
    }


# ── Taint analysis ────────────────────────────────────────────────────────────
class TaintAnalyzer(ast.NodeVisitor):
    """
    Single-pass taint analysis.
    Sources: os.environ, sys.argv, network call return values (requests.get/post, urllib.request).
    Sinks: eval(), exec(), subprocess.Popen/run/call/check_output, os.system/popen.
    Tracks assignments to detect data flowing from source to sink.
    """
    SOURCE_ATTRS = {"environ", "argv"}
    SOURCE_FUNCS = {"get", "post", "urlopen", "read", "recv"}
    SINK_FUNCS   = {"eval", "exec", "system", "popen", "Popen", "run", "call",
                    "check_output", "spawn", "execv", "execve"}

    def __init__(self, filename):
        self.filename = filename
        self.tainted: set = set()   # variable names currently tainted
        self.alerts = []

    # ── source detection ──
    def _is_source(self, node):
        if isinstance(node, ast.Attribute):
            if node.attr in self.SOURCE_ATTRS:
                return True
        if isinstance(node, ast.Call):
            fn = node.func
            if isinstance(fn, ast.Attribute) and fn.attr in self.SOURCE_FUNCS:
                return True
        return False

    def _mark_targets_tainted(self, targets):
        for t in targets:
            if isinstance(t, ast.Name):
                self.tainted.add(t.id)
            elif isinstance(t, ast.Tuple):
                for elt in t.elts:
                    if isinstance(elt, ast.Name):
                        self.tainted.add(elt.id)

    def _find_tainted_in_node(self, node):
        """
        Recursively search an AST node for the first tainted variable name.
        Handles: Name, List, Tuple, BinOp, Call, Subscript, etc.
        Returns the variable name if found, None otherwise.
        """
        if isinstance(node, ast.Name):
            if node.id in self.tainted:
                return node.id
        elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
            for elt in node.elts:
                r = self._find_tainted_in_node(elt)
                if r:
                    return r
        elif isinstance(node, ast.BinOp):
            return self._find_tainted_in_node(node.left) or self._find_tainted_in_node(node.right)
        elif isinstance(node, ast.Call):
            for a in node.args:
                r = self._find_tainted_in_node(a)
                if r:
                    return r
        elif isinstance(node, ast.Subscript):
            return self._find_tainted_in_node(node.value)
        return None

    def visit_Assign(self, node):
        if self._is_source(node.value):
            self._mark_targets_tainted(node.targets)
        # Propagate: if RHS references tainted variable, LHS becomes tainted
        elif isinstance(node.value, ast.Name) and node.value.id in self.tainted:
            self._mark_targets_tainted(node.targets)
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        if func_name in self.SINK_FUNCS:
            for arg in node.args:
                tainted_var = self._find_tainted_in_node(arg)
                if tainted_var:
                    # Build-tool files (distutils, wheel, build_ext, etc.) legitimately
                    # read env vars like PKG_CONFIG or CFLAGS and pass them to subprocess.
                    # Downgrade severity and don't set dangerous_ast_detected.
                    is_build = _is_build_tool_file(self.filename)
                    severity   = "medium" if is_build else "high"
                    confidence = "medium" if is_build else "high"
                    f = make_finding(
                        self.filename, node.lineno, severity, "taint_flow",
                        f"Tainted data from external source flows into sink '{func_name}' "
                        f"(variable: '{tainted_var}')"
                        + (" [build-tool context]" if is_build else ""),
                        confidence
                    )
                    if f:
                        self.alerts.append(f)
        self.generic_visit(node)


# ── Main AST visitor ──────────────────────────────────────────────────────────
class StaticASTVisitor(ast.NodeVisitor):
    def __init__(self, filename, npm_hooks=None, package_name=None):
        self.filename = filename
        self.npm_hooks = npm_hooks or set()
        self.package_name = package_name
        self.alerts = []
        self.imports = set()
        self.obfuscation_detected = False
        self.dangerous_ast_detected = False

    def _is_hook(self):
        file_lower = self.filename.lower()
        basename_lower = os.path.basename(file_lower)
        return (
            basename_lower == "setup.py" or
            basename_lower in self.npm_hooks or
            any(h in basename_lower for h in ["preinstall", "postinstall"]) or
            (basename_lower.startswith("install") and basename_lower.endswith(".py"))
        )

    def _add(self, finding):
        if finding is not None:
            self.alerts.append(finding)

    def visit_Import(self, node):
        for alias in node.names:
            self.imports.add(alias.name)
            if self._is_hook() and alias.name in ["socket", "subprocess", "requests", "urllib", "http", "pty"]:
                self.dangerous_ast_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "setup_hook_danger",
                    f"Install hook imports network/process library: '{alias.name}'",
                    "high", self.package_name
                ))
        self.generic_visit(node)

    def visit_ImportFrom(self, node):
        if node.module:
            self.imports.add(node.module)
            if self._is_hook() and any(m in node.module for m in ["socket", "subprocess", "requests", "urllib", "http", "pty"]):
                self.dangerous_ast_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "setup_hook_danger",
                    f"Install hook imports from network/process library: '{node.module}'",
                    "high", self.package_name
                ))
        self.generic_visit(node)

    def visit_Call(self, node):
        func_name = ""
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
        elif isinstance(node.func, ast.Attribute):
            func_name = node.func.attr

        is_hook = self._is_hook()

        # ── eval / exec ──
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
                confidence = "high"
            else:
                severity = "medium"
                confidence = "medium"

            self._add(make_finding(
                self.filename, node.lineno, severity, "dynamic_execution",
                f"Dynamic execution '{func_name}' (suspicious decode chain: {is_suspicious_eval or is_hook})",
                confidence, self.package_name
            ))

        # ── subprocess / network in setup hooks ──
        if is_hook and func_name in ["system", "popen", "spawn", "run", "Popen", "call",
                                     "check_output", "connect", "get", "post", "urlopen"]:
            self.dangerous_ast_detected = True
            self._add(make_finding(
                self.filename, node.lineno, "high", "setup_hook_danger",
                f"Install hook executes subprocess or network call: '{func_name}'",
                "high", self.package_name
            ))

        # ── getattr obfuscation ──
        if func_name == "getattr" and len(node.args) >= 2:
            if isinstance(node.args[1], ast.BinOp) and is_constant_concatenation(node.args[1]):
                self.obfuscation_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "obfuscation",
                    "getattr obfuscation with concatenated attribute string",
                    "high", self.package_name
                ))

        # ── chr() array obfuscation ──
        # Detect chr(x)+chr(y)+... used to reconstruct dangerous strings
        decoded = _extract_chr_string(node)
        if decoded is None and isinstance(node, ast.BinOp):
            pass  # handled below as a BinOp
        if decoded is not None and len(decoded) >= 3:
            dangerous_words = ["eval", "exec", "system", "popen", "import", "socket", "subprocess"]
            if any(w in decoded.lower() for w in dangerous_words):
                self.obfuscation_detected = True
                self.dangerous_ast_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "chr_obfuscation",
                    f"chr()-array reconstructs dangerous string: '{decoded}'",
                    "high", self.package_name
                ))

        self.generic_visit(node)

    def visit_BinOp(self, node):
        # chr() chain at BinOp level
        decoded = _extract_chr_string(node)
        if decoded and len(decoded) >= 3:
            dangerous_words = ["eval", "exec", "system", "popen", "import", "socket", "subprocess"]
            if any(w in decoded.lower() for w in dangerous_words):
                self.obfuscation_detected = True
                self.dangerous_ast_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "chr_obfuscation",
                    f"chr()-array reconstructs dangerous string: '{decoded}'",
                    "high", self.package_name
                ))

        # String split/join obfuscation: ''.join(['ev','al']) or similar
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            # Look for constant+constant where result spells something dangerous
            if is_constant_concatenation(node):
                # Evaluate the concatenation
                def eval_concat(n):
                    if isinstance(n, ast.Constant) and isinstance(n.value, str):
                        return n.value
                    if isinstance(n, ast.BinOp) and isinstance(n.op, ast.Add):
                        l = eval_concat(n.left)
                        r = eval_concat(n.right)
                        if l is not None and r is not None:
                            return l + r
                    return None
                result = eval_concat(node)
                if result and len(result) >= 3:
                    dangerous_words = ["eval", "exec", "system", "subprocess", "socket", "popen"]
                    if any(w in result.lower() for w in dangerous_words):
                        self.obfuscation_detected = True
                        self.dangerous_ast_detected = True
                        self._add(make_finding(
                            self.filename, getattr(node, 'lineno', 0), "high", "string_split_obfusc",
                            f"String concatenation reconstructs dangerous identifier: '{result}'",
                            "high", self.package_name
                        ))
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            val = node.value
            ent = entropy(val)
            whitespace_count = sum(1 for c in val if c.isspace())
            whitespace_ratio = whitespace_count / len(val) if val else 0

            if len(val) > 120 and ent > 4.8 and whitespace_ratio < 0.02:
                self.obfuscation_detected = True
                self._add(make_finding(
                    self.filename, node.lineno, "high", "high_entropy",
                    f"High-entropy string literal (len={len(val)}, entropy={ent:.2f}, ws_ratio={whitespace_ratio:.2%})",
                    "medium", self.package_name
                ))

            is_hook = self._is_hook()
            for pattern in SUSPICIOUS_STRINGS:
                if re.search(pattern, val, re.IGNORECASE):
                    is_critical_path = any(p in pattern for p in ["passwd", "ssh", "credentials"])
                    if is_hook or is_critical_path:
                        self.dangerous_ast_detected = True
                        severity = "high"
                        confidence = "high"
                    else:
                        severity = "medium"
                        confidence = "medium"
                    self._add(make_finding(
                        self.filename, node.lineno, severity, "sensitive_data",
                        f"Sensitive pattern/file match: '{pattern}'",
                        confidence, self.package_name
                    ))

            # IoC: check string literals for known C2 domains
            for ioc_pat in IOC_DOMAINS:
                if re.search(ioc_pat, val, re.IGNORECASE):
                    self.dangerous_ast_detected = True
                    self._add(make_finding(
                        self.filename, node.lineno, "high", "ioc_match",
                        f"Known IoC pattern in string literal: '{ioc_pat}'",
                        "high", self.package_name
                    ))
                    break

        self.generic_visit(node)


# ── Python file analysis ──────────────────────────────────────────────────────
def analyze_python_file(filepath, relative_path, npm_hooks=None, package_name=None):
    alerts = []
    obfuscation_detected = False
    dangerous_ast_detected = False

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        # YARA
        try:
            matches = compiled_yara_rules.match(filepath)
            for match in matches:
                ftype = YARA_RULE_TYPE.get(match.rule, "yara_match")

                _rel_lower     = relative_path.lower()
                _base_lower    = os.path.basename(_rel_lower)
                _is_hook_file  = (
                    _base_lower == "setup.py" or
                    (npm_hooks and _base_lower in npm_hooks) or
                    any(h in _base_lower for h in ["preinstall", "postinstall"]) or
                    (_base_lower.startswith("install") and _base_lower.endswith(".py"))
                )
                _is_build      = _is_build_tool_file(relative_path)

                if match.rule in ["python_obfuscated_eval", "js_obfuscated_eval", "chr_array_obfuscation"]:
                    obfuscation_detected = True
                elif match.rule in ["suspicious_exfiltration", "telegram_bot_token",
                                    "discord_bot_token", "python_reverse_shell"]:
                    dangerous_ast_detected = True
                elif match.rule == "env_var_exfil":
                    # env_var_exfil: "reads env var + makes network call" matches almost every
                    # HTTP library (requests, urllib3, httpx…). Only meaningful in install hooks.
                    if not _is_hook_file:
                        continue          # skip entirely outside of install hooks
                    dangerous_ast_detected = True
                elif match.rule == "sensitive_files_access":
                    has_passwd_or_ssh = any(
                        "passwd" in str(sm[2]).lower() or "ssh" in str(sm[2]).lower() or
                        "credentials" in str(sm[2]).lower()
                        for sm in match.strings
                    )
                    if _is_hook_file or has_passwd_or_ssh:
                        dangerous_ast_detected = True

                f_obj = make_finding(
                    relative_path, 1, "high", ftype,
                    f"YARA match: {match.rule} — {match.meta.get('description', '')}",
                    "high", package_name
                )
                if f_obj:
                    alerts.append(f_obj)
        except Exception:
            pass

        # AST visitor
        try:
            tree = ast.parse(source, filename=filepath)
            visitor = StaticASTVisitor(relative_path, npm_hooks=npm_hooks, package_name=package_name)
            visitor.visit(tree)
            alerts.extend(visitor.alerts)
            if visitor.obfuscation_detected:
                obfuscation_detected = True
            if visitor.dangerous_ast_detected:
                dangerous_ast_detected = True
        except SyntaxError:
            alerts.append(make_finding(
                relative_path, 1, "low", "syntax_error",
                "Unable to parse Python AST", "low", package_name
            ))

        # Taint analysis
        try:
            tree = ast.parse(source, filename=filepath)
            taint = TaintAnalyzer(relative_path)
            taint.visit(tree)
            for a in taint.alerts:
                dangerous_ast_detected = True
                alerts.append(a)
        except Exception:
            pass

    except Exception as e:
        alerts.append(make_finding(
            relative_path, 0, "low", "error",
            f"Error scanning file: {e}", "low", package_name
        ))

    return [a for a in alerts if a is not None], obfuscation_detected, dangerous_ast_detected


# ── Generic (JS / shell) file analysis ───────────────────────────────────────
def analyze_generic_file(filepath, relative_path, npm_hooks=None, package_name=None):
    alerts = []
    obfuscation_detected = False
    dangerous_ast_detected = False

    try:
        with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
            source = f.read()

        # YARA
        try:
            matches = compiled_yara_rules.match(filepath)
            for match in matches:
                ftype = YARA_RULE_TYPE.get(match.rule, "yara_match")

                _rel_lower    = relative_path.lower()
                _base_lower   = os.path.basename(_rel_lower)
                _is_hook_file = (
                    (npm_hooks and _base_lower in npm_hooks) or
                    any(h in _base_lower for h in ["preinstall", "postinstall"])
                )
                _is_build     = _is_build_tool_file(relative_path)

                if match.rule in ["python_obfuscated_eval", "js_obfuscated_eval", "chr_array_obfuscation"]:
                    obfuscation_detected = True
                elif match.rule in ["suspicious_exfiltration", "telegram_bot_token",
                                    "discord_bot_token", "python_reverse_shell"]:
                    dangerous_ast_detected = True
                elif match.rule == "env_var_exfil":
                    if not _is_hook_file:
                        continue          # skip entirely outside of install hooks
                    dangerous_ast_detected = True
                elif match.rule == "sensitive_files_access":
                    has_passwd_or_ssh = any(
                        "passwd" in str(sm[2]).lower() or "ssh" in str(sm[2]).lower() or
                        "credentials" in str(sm[2]).lower()
                        for sm in match.strings
                    )
                    if _is_hook_file or has_passwd_or_ssh:
                        dangerous_ast_detected = True

                f_obj = make_finding(
                    relative_path, 1, "high", ftype,
                    f"YARA match: {match.rule} — {match.meta.get('description', '')}",
                    "high", package_name
                )
                if f_obj:
                    alerts.append(f_obj)
        except Exception:
            pass

        # Line-by-line
        lines = source.splitlines()
        _file_lower   = relative_path.lower()
        _base_lower   = os.path.basename(_file_lower)
        is_hook_file  = (
            (npm_hooks and _base_lower in npm_hooks) or
            any(h in _base_lower for h in ["preinstall", "postinstall"])
        )
        is_build_file = _is_build_tool_file(relative_path)

        for i, line in enumerate(lines, 1):
            if "child_process" in line or "exec(" in line or "spawn(" in line:
                if is_hook_file:
                    dangerous_ast_detected = True
                    severity = "high"
                    confidence = "high"
                else:
                    severity = "medium"
                    confidence = "medium"
                f_obj = make_finding(
                    relative_path, i, severity, "process_spawn",
                    f"Process execution pattern: '{line.strip()[:60]}'",
                    confidence, package_name
                )
                if f_obj:
                    alerts.append(f_obj)

            # Word-boundary check: only flag eval( / Function( as actual calls,
            # not as substrings of identifiers like isFunction() or assertIsFunction().
            if JS_EVAL_PAT.search(line):
                is_suspicious_eval = "base64" in line or "hex" in line or "Buffer.from" in line
                if is_hook_file or is_suspicious_eval:
                    dangerous_ast_detected = True
                    severity = "high"
                    confidence = "high"
                else:
                    severity = "medium"
                    confidence = "medium"
                f_obj = make_finding(
                    relative_path, i, severity, "dynamic_execution",
                    f"Dynamic execution pattern: '{line.strip()[:60]}'",
                    confidence, package_name
                )
                if f_obj:
                    alerts.append(f_obj)

            # IoC in line
            for ioc_pat in IOC_DOMAINS:
                if re.search(ioc_pat, line, re.IGNORECASE):
                    dangerous_ast_detected = True
                    f_obj = make_finding(
                        relative_path, i, "high", "ioc_match",
                        f"Known IoC domain pattern in source: '{ioc_pat}'",
                        "high", package_name
                    )
                    if f_obj:
                        alerts.append(f_obj)
                    break

            # High-entropy quoted strings
            quoted_strings = re.findall(r"['\"`](.*?)['\"`]", line)
            for qs in quoted_strings:
                ent = entropy(qs)
                whitespace_count = sum(1 for c in qs if c.isspace())
                whitespace_ratio = whitespace_count / len(qs) if qs else 0
                if len(qs) > 120 and ent > 4.8 and whitespace_ratio < 0.02:
                    obfuscation_detected = True
                    f_obj = make_finding(
                        relative_path, i, "high", "high_entropy",
                        f"High-entropy JS string (len={len(qs)}, entropy={ent:.2f}, ws_ratio={whitespace_ratio:.2%})",
                        "medium", package_name
                    )
                    if f_obj:
                        alerts.append(f_obj)

            for pattern in SUSPICIOUS_STRINGS:
                if re.search(pattern, line, re.IGNORECASE):
                    is_critical_path = any(p in pattern for p in ["passwd", "ssh", "credentials"])
                    if is_hook_file or is_critical_path:
                        dangerous_ast_detected = True
                        severity = "high"
                        confidence = "high"
                    else:
                        severity = "medium"
                        confidence = "medium"
                    f_obj = make_finding(
                        relative_path, i, severity, "sensitive_data",
                        f"Sensitive pattern match: '{pattern}'",
                        confidence, package_name
                    )
                    if f_obj:
                        alerts.append(f_obj)

    except Exception as e:
        f_obj = make_finding(
            relative_path, 0, "low", "error",
            f"Error scanning file: {e}", "low", package_name
        )
        if f_obj:
            alerts.append(f_obj)

    return [a for a in alerts if a is not None], obfuscation_detected, dangerous_ast_detected


# ── NPM install hook detection ────────────────────────────────────────────────
def get_npm_install_hooks(directory_path):
    hook_files = set()
    package_json_path = os.path.join(directory_path, "package.json")
    if not os.path.exists(package_json_path):
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
                        for word in cmd.split():
                            word_clean = word.strip("`'\"&|;()").strip()
                            if word_clean.endswith(".js") or word_clean.endswith(".sh"):
                                hook_files.add(os.path.basename(word_clean).lower())
        except Exception:
            pass
    return hook_files


# ── Directory scanner ─────────────────────────────────────────────────────────
def scan_directory(directory_path, package_name=None):
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
            skip_dirs = {"tests", "test", "testing", "docs", "doc", "examples", "example",
                         "benchmarks", "benchmark", ".github", ".git", ".tox", "venv", ".venv", "htmlcov"}
            if any(p in skip_dirs for p in parts):
                continue

            file_lower = file.lower()
            if file_lower.startswith("test_") or file_lower.endswith("_test.py") or file_lower == "conftest.py":
                continue
            # Skip minified JS — high entropy by design, would produce many false positives
            if file_lower.endswith(".min.js") or file_lower.endswith(".min.css"):
                continue

            ext = os.path.splitext(file)[1].lower()
            if ext not in ALLOWED_EXTENSIONS and file_lower not in ["setup.py", "package.json"]:
                continue

            files_scanned += 1
            if ext == ".py":
                file_alerts, obf, ast_dang = analyze_python_file(
                    filepath, relpath, npm_hooks=npm_hooks, package_name=package_name)
            else:
                file_alerts, obf, ast_dang = analyze_generic_file(
                    filepath, relpath, npm_hooks=npm_hooks, package_name=package_name)

            alerts.extend(file_alerts)
            if obf:
                obfuscation_detected = True
            if ast_dang:
                dangerous_ast_detected = True

    return alerts, files_scanned, obfuscation_detected, dangerous_ast_detected


# ── Public entry point ────────────────────────────────────────────────────────
def scan_static(package_name, ecosystem, download_url=None):
    results = {
        "typosquatting": None,
        "alerts": [],
        "files_scanned": 0,
        "obfuscation_detected": False,
        "dangerous_ast_detected": False,
        "taint_flows_detected": False,
        "ioc_matches": [],
        "success": False,
        "error": None
    }

    # 1. Typosquatting
    typo = check_typosquatting(package_name, ecosystem)
    if typo:
        results["typosquatting"] = typo
        f = make_finding("package_name", 0, "high", "typosquatting", typo["message"], "high", package_name)
        if f:
            results["alerts"].append(f)

    if not download_url:
        results["error"] = "No download URL available to fetch package contents."
        return results

    # 2. Download + extract
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
                results["error"] = f"Failed to download package archive (HTTP {response.status_code})"
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

        alerts, files_scanned, obf, ast_dang = scan_directory(extract_path, package_name=package_name)
        results["alerts"].extend(alerts)
        results["files_scanned"] = files_scanned
        results["obfuscation_detected"] = obf
        results["dangerous_ast_detected"] = ast_dang
        results["taint_flows_detected"] = any(a.get("type") == "taint_flow" for a in alerts)
        results["ioc_matches"] = [a for a in alerts if a.get("type") == "ioc_match"]
        results["success"] = True

        import shutil
        shutil.rmtree(temp_dir, ignore_errors=True)

    except Exception as e:
        results["error"] = f"Error during static scan: {e}"

    return results

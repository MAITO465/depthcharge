"""
Depthcharge Demo — Intentionally Vulnerable Flask Application
Mohammed Ait Ourajli — Dynamic Sandbox & OWASP ZAP Target

PURPOSE:
  This application intentionally contains security vulnerabilities
  to serve as a demonstration target for:
    1. OWASP ZAP DAST baseline scan
    2. Depthcharge Docker sandbox behavioral analysis
    3. Semgrep/Bandit static analysis demonstration

  DO NOT deploy this application in production.
  Every vulnerability here is intentional and documented.

VULNERABILITIES INCLUDED:
  - SQL Injection (CWE-89)
  - Command Injection (CWE-78)
  - Hardcoded credentials (CWE-798)
  - Path traversal (CWE-22)
  - Insecure deserialization via pickle (CWE-502)
  - Missing authentication on admin endpoints (CWE-306)
  - Reflected XSS (CWE-79)
  - Sensitive data in URL (CWE-598)
"""

import os
import sqlite3
import subprocess
import pickle
import base64
from flask import Flask, request, jsonify, render_template_string

app = Flask(__name__)

# ── CWE-798: Hardcoded credentials ─────────────────────────────────────────
# nosec — intentional for demo
ADMIN_PASSWORD = "admin123"           # noqa: S105
SECRET_API_KEY = "sk-1234567890abcdef"  # noqa: S105
DB_PATH = "/tmp/demo_users.db"

HTML_BASE = """
<!DOCTYPE html>
<html>
<head><title>Depthcharge Demo App</title>
<style>
  body { font-family: monospace; background: #0a0a0a; color: #00ff88; padding: 40px; }
  h1 { color: #00c8ff; } pre { background: #111; padding: 16px; border-radius: 8px; }
  a { color: #00c8ff; } input, button { background: #111; color: #ccc; border: 1px solid #333; padding: 6px 12px; }
  .vuln-badge { background: #ff2d6b22; color: #ff2d6b; border: 1px solid #ff2d6b44;
                padding: 2px 8px; border-radius: 4px; font-size: 0.8em; margin-left: 8px; }
</style>
</head>
<body>
<h1>🔓 Depthcharge Vulnerable Demo App</h1>
<p>Intentionally insecure — DAST / sandbox training target</p>
<hr>
{% block content %}{% endblock %}
</body>
</html>
"""

def init_db():
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT,
            password TEXT,
            email TEXT,
            role TEXT DEFAULT 'user'
        )
    """)
    conn.execute("INSERT OR IGNORE INTO users VALUES (1,'admin','admin123','admin@demo.local','admin')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (2,'alice','password','alice@demo.local','user')")
    conn.execute("INSERT OR IGNORE INTO users VALUES (3,'bob','qwerty','bob@demo.local','user')")
    conn.commit()
    conn.close()


@app.route("/")
def index():
    return render_template_string(HTML_BASE.replace(
        "{% block content %}{% endblock %}",
        """
        <h2>Endpoints</h2>
        <ul>
          <li><a href="/search?q=alice">/search?q= </a> <span class="vuln-badge">SQL Injection</span></li>
          <li><a href="/ping?host=127.0.0.1">/ping?host= </a> <span class="vuln-badge">Command Injection</span></li>
          <li><a href="/file?name=app.py">/file?name= </a> <span class="vuln-badge">Path Traversal</span></li>
          <li><a href="/admin">/admin </a> <span class="vuln-badge">Missing Auth</span></li>
          <li><a href="/greet?name=World">/greet?name= </a> <span class="vuln-badge">Reflected XSS</span></li>
          <li><a href="/deserialize">/deserialize </a> <span class="vuln-badge">Insecure Deserialization</span></li>
        </ul>
        """
    ))


# ── CWE-89: SQL Injection ──────────────────────────────────────────────────
@app.route("/search")
def search():
    """
    Vulnerable: unsanitized user input directly interpolated into SQL query.
    Attack: /search?q=' OR '1'='1
    Attack: /search?q=' UNION SELECT username,password,email,role,id FROM users--
    """
    q = request.args.get("q", "")
    conn = sqlite3.connect(DB_PATH)
    # nosec — intentional SQL injection
    query = f"SELECT * FROM users WHERE username = '{q}'"  # noqa: S608
    try:
        rows = conn.execute(query).fetchall()
    except Exception as e:
        rows = [str(e)]
    conn.close()
    return jsonify({"query": query, "results": [list(r) for r in rows]})


# ── CWE-78: Command Injection ──────────────────────────────────────────────
@app.route("/ping")
def ping():
    """
    Vulnerable: shell=True with unsanitized host parameter.
    Attack: /ping?host=127.0.0.1; cat /etc/passwd
    Attack: /ping?host=127.0.0.1 && whoami
    """
    host = request.args.get("host", "127.0.0.1")
    # nosec — intentional command injection
    result = subprocess.check_output(  # noqa: S602
        f"ping -c 1 {host}", shell=True, stderr=subprocess.STDOUT, timeout=5
    ).decode()
    return jsonify({"host": host, "output": result})


# ── CWE-22: Path Traversal ─────────────────────────────────────────────────
@app.route("/file")
def read_file():
    """
    Vulnerable: no path normalization or sandboxing.
    Attack: /file?name=../../../../etc/passwd
    Attack: /file?name=../../../../etc/shadow
    """
    name = request.args.get("name", "app.py")
    base = os.path.dirname(os.path.abspath(__file__))
    # nosec — intentional path traversal
    path = os.path.join(base, name)
    try:
        with open(path) as f:  # noqa: S603
            content = f.read()
        return jsonify({"path": path, "content": content})
    except Exception as e:
        return jsonify({"error": str(e)}), 404


# ── CWE-306: Missing Authentication ───────────────────────────────────────
@app.route("/admin")
def admin():
    """
    Vulnerable: no authentication check — anyone can access admin panel.
    ZAP will flag this as an unauthenticated admin endpoint.
    """
    conn = sqlite3.connect(DB_PATH)
    users = conn.execute("SELECT * FROM users").fetchall()
    conn.close()
    return jsonify({
        "message": "Admin panel — no authentication required",
        "secret_key": SECRET_API_KEY,   # also leaks the hardcoded API key
        "users": [list(u) for u in users]
    })


# ── CWE-79: Reflected XSS ─────────────────────────────────────────────────
@app.route("/greet")
def greet():
    """
    Vulnerable: user input reflected directly into HTML without escaping.
    Attack: /greet?name=<script>alert('XSS')</script>
    """
    name = request.args.get("name", "World")
    # nosec — intentional XSS
    return f"<h1>Hello, {name}!</h1>"  # noqa: S703


# ── CWE-502: Insecure Deserialization ─────────────────────────────────────
@app.route("/deserialize", methods=["GET", "POST"])
def deserialize():
    """
    Vulnerable: pickle.loads on user-supplied base64 data.
    Attack payload (generates reverse shell pickle):
      import pickle, base64, os
      class Exploit(object):
          def __reduce__(self):
              return (os.system, ('id',))
      print(base64.b64encode(pickle.dumps(Exploit())).decode())
    """
    if request.method == "POST":
        data = request.json.get("data", "")
        try:
            # nosec — intentional insecure deserialization
            obj = pickle.loads(base64.b64decode(data))  # noqa: S301
            return jsonify({"result": str(obj)})
        except Exception as e:
            return jsonify({"error": str(e)}), 400
    return jsonify({
        "description": "POST JSON with {\"data\": \"<base64-encoded-pickle>\"} to deserialize",
        "warning": "This endpoint is intentionally vulnerable to pickle deserialization attacks"
    })


if __name__ == "__main__":
    init_db()
    print("=" * 60)
    print("  Depthcharge Vulnerable Demo App")
    print("  INTENTIONALLY INSECURE — for testing only")
    print("  http://127.0.0.1:5050")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5050, debug=False)

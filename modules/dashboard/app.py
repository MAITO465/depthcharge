import os
import sys
import sqlite3
import json
import threading
import time as _time
from flask import Flask, render_template, jsonify, request, Response, stream_with_context

# Ensure parent directory is in sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from modules.reputation.checker import scan_reputation
from modules.static.analyzer import scan_static
from modules.sandbox.runner import scan_dynamic, is_docker_available
from scorer import calculate_score
from depthcharge import generate_html_report, generate_markdown_report

try:
    from modules.report.pdf_generator import generate_pdf_report
    pdf_available = True
except ImportError:
    pdf_available = False

import tempfile
from flask import send_file

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "data", "depthcharge.db")

# ── Live scan progress store ──────────────────────────────────────────────────
# Maps scan_id → list of progress event dicts.
# Written by the background scan thread; read by the SSE stream endpoint.
_progress: dict = {}

def _emit(scan_id: int, phase: str, status: str, message: str) -> None:
    """Append a progress event for the given scan."""
    _progress.setdefault(scan_id, []).append({
        "phase": phase, "status": status, "message": message
    })

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            version TEXT,
            score INTEGER DEFAULT -1,
            risk_level TEXT DEFAULT 'Scanning',
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation_data TEXT,
            static_data TEXT,
            dynamic_data TEXT,
            reasons TEXT
        )
    """)
    conn.commit()
    conn.close()

def run_scan_in_background(scan_id, package_name, ecosystem, skip_reputation=False, skip_static=False, skip_dynamic=False):
    """
    Executes the reputation, static, and dynamic scan, then updates the database.
    Emits SSE-compatible progress events into _progress[scan_id] as each phase completes.
    """
    _progress[scan_id] = []
    try:
        # ── Phase 1: Reputation ───────────────────────────────────────────────
        _emit(scan_id, "reputation", "running", "Querying PyPI registry and OSV vulnerability database…")
        rep_results = scan_reputation(package_name, ecosystem)

        if skip_reputation:
            rep_results["vulnerabilities"] = []
            rep_results["typosquatting_detected"] = False
            rep_results["is_suspiciously_new"] = False
            rep_results["known_malicious"] = False
            rep_results["malware_database_match"] = False

        if not rep_results.get("exists"):
            if rep_results.get("typosquatting_detected"):
                _emit(scan_id, "reputation", "warn", "Package not found — possible typosquatting detected")
                typo_info   = rep_results.get("typosquatting_info") or {}
                typo_target = typo_info.get("target", "a known package")
                typo_dist   = typo_info.get("distance", "?")
                typo_msg    = typo_info.get("message", "")
                # Surface typosquatting as a real finding so it appears in the Static tab
                typo_finding = {
                    "type":             "typosquatting",
                    "severity":         "high",
                    "confidence":       "High",
                    "mitre_id":         "T1195.001",
                    "mitre_technique":  "Compromise Software Dependencies and Development Tools",
                    "message":          (
                        f"'{package_name}' does not exist on PyPI but is suspiciously similar to the popular "
                        f"package '{typo_target}' (edit distance: {typo_dist}). "
                        f"Attackers register near-identical names to intercept installs via typos. "
                        f"Original signal: {typo_msg}"
                    ),
                    "file":    "PyPI Registry (name-similarity analysis)",
                    "line":    0,
                    "compliance": ["NIST SP 800-161 SA-12", "NIS2 Directive Art.21", "DORA Art.5"],
                }
                static_results  = {
                    "typosquatting": typo_info,
                    "alerts":        [typo_finding],
                    "files_scanned": 0,
                    "obfuscation_detected":   False,
                    "dangerous_ast_detected": False,
                    "success": False,
                }
                dynamic_results = {
                    "docker_available": False,
                    "events": [{
                        "type":    "INSTALL_BLOCKED",
                        "details": (
                            f"pip install {package_name} → No matching distribution found. "
                            f"Package does not exist on PyPI — installation was blocked at the registry level. "
                            f"Likely typosquat of '{typo_target}'."
                        ),
                    }],
                }
                score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
                conn = get_db_connection(); cursor = conn.cursor()
                cursor.execute("UPDATE scans SET version='N/A', score=?, risk_level=?, reputation_data=?, static_data=?, dynamic_data=?, reasons=? WHERE id=?",
                    (score_data["score"], score_data["risk_level"], json.dumps(rep_results), json.dumps(static_results), json.dumps(dynamic_results), json.dumps(score_data["reasons"]), scan_id))
                conn.commit(); conn.close()
                _emit(scan_id, "complete", "done", f"Score: {score_data['score']}/100 — {score_data['risk_level']}")
                return
            error_msg = rep_results.get("error", "Package not found")
            _emit(scan_id, "reputation", "error", error_msg)
            _emit(scan_id, "complete",   "error", "Scan failed")
            update_scan_failed(scan_id, error_msg)
            return

        vuln_count = len(rep_results.get("vulnerabilities", []))
        ver        = rep_results.get("version", "?")
        _emit(scan_id, "reputation", "done",
              f"v{ver} · {rep_results.get('releases_count', 0)} releases · {vuln_count} CVE{'s' if vuln_count != 1 else ''}")

        # ── Phase 2: Static ───────────────────────────────────────────────────
        download_url   = rep_results.get("download_url")
        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            _emit(scan_id, "static", "running", "Downloading source archive and running AST / YARA analysis…")
            static_results = scan_static(package_name, ecosystem, download_url)
            alert_count    = len(static_results.get("alerts", []))
            files_scanned  = static_results.get("files_scanned", 0)
            _emit(scan_id, "static", "done" if alert_count == 0 else "warn",
                  f"{files_scanned} files scanned · {alert_count} alert{'s' if alert_count != 1 else ''} found")
        else:
            _emit(scan_id, "static", "skip", "Static analysis skipped")

        # ── Phase 3: Dynamic ──────────────────────────────────────────────────
        dynamic_results = {"docker_available": False, "events": []}
        if not skip_dynamic:
            _emit(scan_id, "dynamic", "running", "Spawning network-isolated Docker sandbox…")
            dynamic_results = scan_dynamic(package_name, ecosystem, download_url)
            event_count     = len(dynamic_results.get("events", []))
            if dynamic_results.get("error"):
                _emit(scan_id, "dynamic", "warn", f"Sandbox warning: {dynamic_results['error']}")
            else:
                _emit(scan_id, "dynamic", "done" if event_count == 0 else "warn",
                      f"Sandbox complete · {event_count} suspicious event{'s' if event_count != 1 else ''}")
        else:
            _emit(scan_id, "dynamic", "skip", "Sandbox skipped")

        # ── Phase 4: Scoring ──────────────────────────────────────────────────
        _emit(scan_id, "scoring", "running", "Calculating combined risk score…")
        score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
        _emit(scan_id, "scoring", "done", f"Score: {score_data['score']}/100 — {score_data['risk_level']}")

        # ── Persist ───────────────────────────────────────────────────────────
        conn = get_db_connection(); cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans
            SET version=?, score=?, risk_level=?, reputation_data=?, static_data=?, dynamic_data=?, reasons=?
            WHERE id=?
        """, (rep_results.get("version"), score_data["score"], score_data["risk_level"],
              json.dumps(rep_results), json.dumps(static_results), json.dumps(dynamic_results),
              json.dumps(score_data["reasons"]), scan_id))
        conn.commit(); conn.close()

        _emit(scan_id, "complete", "done", f"Analysis complete — {score_data['risk_level']} risk")

    except Exception as e:
        _emit(scan_id, "complete", "error", f"Internal error: {str(e)}")
        update_scan_failed(scan_id, f"Internal Error: {str(e)}")

def update_scan_failed(scan_id, error_msg):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        UPDATE scans
        SET score = 100, risk_level = 'Failed', reasons = ?
        WHERE id = ?
    """, (json.dumps([f"Scan failed: {error_msg}"]), scan_id))
    conn.commit()
    conn.close()

@app.before_request
def strip_conditional_for_static():
    """Strip If-None-Match / If-Modified-Since so Flask never returns 304 for static files."""
    if request.path.startswith('/static/'):
        request.environ.pop('HTTP_IF_NONE_MATCH', None)
        request.environ.pop('HTTP_IF_MODIFIED_SINCE', None)

@app.after_request
def no_cache_static(response):
    """Tell the browser not to cache static files."""
    if request.path.startswith('/static/'):
        response.headers['Cache-Control'] = 'no-cache, no-store, must-revalidate'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
    return response

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/history", methods=["GET"])
def history():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans ORDER BY scanned_at DESC")
    rows = cursor.fetchall()
    conn.close()
    
    results = []
    for r in rows:
        results.append({
            "id": r["id"],
            "package_name": r["package_name"],
            "ecosystem": r["ecosystem"],
            "version": r["version"],
            "score": r["score"],
            "risk_level": r["risk_level"],
            "scanned_at": r["scanned_at"],
            "reasons": json.loads(r["reasons"]) if r["reasons"] else []
        })
    return jsonify(results)

@app.route("/api/scan/<int:scan_id>", methods=["GET"])
def get_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Scan not found"}), 404
        
    return jsonify({
        "id": row["id"],
        "package_name": row["package_name"],
        "ecosystem": row["ecosystem"],
        "version": row["version"],
        "score": row["score"],
        "risk_level": row["risk_level"],
        "scanned_at": row["scanned_at"],
        "reputation_data": json.loads(row["reputation_data"]) if row["reputation_data"] else None,
        "static_data": json.loads(row["static_data"]) if row["static_data"] else None,
        "dynamic_data": json.loads(row["dynamic_data"]) if row["dynamic_data"] else None,
        "reasons": json.loads(row["reasons"]) if row["reasons"] else []
    })

@app.route("/api/scan", methods=["POST"])
def trigger_scan():
    data = request.json or {}
    package_name = data.get("package")
    ecosystem = data.get("ecosystem", "pypi").lower()
    skip_reputation = data.get("skip_reputation", False)
    skip_static = data.get("skip_static", False)
    skip_dynamic = data.get("skip_dynamic", False)
    
    if not package_name:
        return jsonify({"error": "Package name is required"}), 400
        
    if ecosystem not in ["pypi", "npm"]:
        return jsonify({"error": "Invalid ecosystem. Supported: pypi, npm"}), 400
        
    init_db()
    
    # Insert placeholder scan record
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO scans (package_name, ecosystem, risk_level, reasons)
        VALUES (?, ?, 'Scanning', ?)
    """, (package_name, ecosystem, json.dumps(["Scanning package in background..."])))
    scan_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Run scan asynchronously
    threading.Thread(target=run_scan_in_background, args=(scan_id, package_name, ecosystem, skip_reputation, skip_static, skip_dynamic)).start()
    
    return jsonify({
        "message": "Scan triggered",
        "scan_id": scan_id,
        "package_name": package_name,
        "ecosystem": ecosystem
    })

@app.route("/api/scan/<int:scan_id>/export/<export_format>", methods=["GET"])
def export_scan(scan_id, export_format):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
    row = cursor.fetchone()
    conn.close()
    
    if not row:
        return jsonify({"error": "Scan not found"}), 404
        
    if row["score"] == -1:
        return jsonify({"error": "Scan is still in progress"}), 400
        
    # Reconstruct scan result dictionary
    try:
        reputation_data = json.loads(row["reputation_data"]) if row["reputation_data"] else None
        static_data = json.loads(row["static_data"]) if row["static_data"] else None
        dynamic_data = json.loads(row["dynamic_data"]) if row["dynamic_data"] else None
        reasons = json.loads(row["reasons"]) if row["reasons"] else []
    except Exception as e:
        return jsonify({"error": f"Failed to parse scan data: {str(e)}"}), 500
        
    scan_res = {
        "score": row["score"],
        "risk_level": row["risk_level"],
        "reasons": reasons,
        "reputation": reputation_data,
        "static": static_data,
        "dynamic": dynamic_data
    }
    
    pkg_name = row["package_name"]
    results = {pkg_name: scan_res}
    
    # Generate to temporary file
    temp_dir = tempfile.mkdtemp()
    
    if export_format == "pdf":
        if not pdf_available:
            return jsonify({"error": "PDF generation library (reportlab) is not installed on the backend. Please install it using 'pip install reportlab' to enable PDF exports."}), 400
        file_path = os.path.join(temp_dir, f"depthcharge_audit_{pkg_name}.pdf")
        try:
            generate_pdf_report(results, file_path)
        except Exception as e:
            return jsonify({"error": f"PDF Generation Error: {str(e)}"}), 500
        mimetype = "application/pdf"
        download_name = f"depthcharge_audit_{pkg_name}.pdf"
        
    elif export_format == "html":
        file_path = os.path.join(temp_dir, f"depthcharge_audit_{pkg_name}.html")
        try:
            generate_html_report(results, file_path)
        except Exception as e:
            return jsonify({"error": f"HTML Generation Error: {str(e)}"}), 500
        mimetype = "text/html"
        download_name = f"depthcharge_audit_{pkg_name}.html"
        
    elif export_format == "md":
        file_path = os.path.join(temp_dir, f"depthcharge_audit_{pkg_name}.md")
        try:
            generate_markdown_report(results, file_path)
        except Exception as e:
            return jsonify({"error": f"Markdown Generation Error: {str(e)}"}), 500
        mimetype = "text/markdown"
        download_name = f"depthcharge_audit_{pkg_name}.md"
        
    else:
        return jsonify({"error": "Unsupported export format. Supported: pdf, html, md"}), 400
        
    return send_file(
        file_path,
        mimetype=mimetype,
        as_attachment=True,
        download_name=download_name
    )

@app.route("/api/scan/<int:scan_id>", methods=["DELETE"])
def delete_scan(scan_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM scans WHERE id = ?", (scan_id,))
    conn.commit()
    deleted = cursor.rowcount > 0
    conn.close()
    if deleted:
        return jsonify({"message": "Scan deleted"})
    return jsonify({"error": "Scan not found"}), 404

@app.route("/api/stats", methods=["GET"])
def get_stats():
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) as total, AVG(CASE WHEN score >= 0 THEN score END) as avg_score, SUM(CASE WHEN risk_level = 'High' THEN 1 ELSE 0 END) as high_count, SUM(CASE WHEN score >= 0 AND score < 15 THEN 1 ELSE 0 END) as safe_count FROM scans")
    row = cursor.fetchone()
    conn.close()
    return jsonify({
        "total_scans": row["total"] or 0,
        "avg_score": round(row["avg_score"] or 0, 1),
        "high_risk_count": row["high_count"] or 0,
        "safe_count": row["safe_count"] or 0
    })

@app.route("/api/findings", methods=["GET"])
def get_findings():
    """All static analysis findings across all completed scans, with optional filters."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, package_name, ecosystem, version, scanned_at, static_data
        FROM scans WHERE score >= 0 AND static_data IS NOT NULL
        ORDER BY scanned_at DESC
    """)
    rows = cursor.fetchall()
    conn.close()

    findings = []
    for row in rows:
        static = json.loads(row["static_data"]) if row["static_data"] else {}
        for a in static.get("alerts", []):
            findings.append({
                "scan_id":      row["id"],
                "package_name": row["package_name"],
                "ecosystem":    row["ecosystem"],
                "version":      row["version"],
                "scanned_at":   row["scanned_at"],
                **a
            })

    sev = request.args.get("severity")
    ftype = request.args.get("type")
    pkg = request.args.get("package")
    if sev:   findings = [f for f in findings if f.get("severity") == sev]
    if ftype: findings = [f for f in findings if f.get("type") == ftype]
    if pkg:   findings = [f for f in findings if pkg.lower() in f.get("package_name", "").lower()]

    return jsonify(findings)


@app.route("/api/inventory", methods=["GET"])
def get_inventory():
    """Package inventory — one row per unique (name, ecosystem) with score history."""
    init_db()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='package_inventory'")
    if not cursor.fetchone():
        conn.close()
        return jsonify([])
    cursor.execute("""
        SELECT package_name, ecosystem, first_seen, last_seen, last_version,
               last_score, last_risk_level, scan_count, score_history
        FROM package_inventory ORDER BY last_seen DESC
    """)
    rows = cursor.fetchall()
    conn.close()
    return jsonify([{
        "package_name":   r["package_name"],
        "ecosystem":      r["ecosystem"],
        "first_seen":     r["first_seen"],
        "last_seen":      r["last_seen"],
        "last_version":   r["last_version"],
        "last_score":     r["last_score"],
        "last_risk_level":r["last_risk_level"],
        "scan_count":     r["scan_count"],
        "score_history":  json.loads(r["score_history"]) if r["score_history"] else []
    } for r in rows])


@app.route("/api/scan/bulk", methods=["POST"])
def bulk_scan():
    """Parse requirements.txt content and start background scans for every package."""
    data = request.json or {}
    content  = data.get("content", "")
    ecosystem = data.get("ecosystem", "pypi").lower()
    if not content:
        return jsonify({"error": "No content provided"}), 400

    scan_ids = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        pkg_name = re.split(r'[>=<!=\[\];@ ]', line)[0].strip()
        if not pkg_name:
            continue
        init_db()
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO scans (package_name, ecosystem, risk_level, reasons) VALUES (?,?,'Scanning',?)",
            (pkg_name, ecosystem, json.dumps(["Scanning package in background..."]))
        )
        scan_id = cursor.lastrowid
        conn.commit()
        conn.close()
        threading.Thread(target=run_scan_in_background,
                         args=(scan_id, pkg_name, ecosystem, False, False, False)).start()
        scan_ids.append({"package": pkg_name, "scan_id": scan_id})

    return jsonify({"scans": scan_ids, "total": len(scan_ids)})


@app.route("/api/scan/<int:scan_id>/stream", methods=["GET"])
def scan_stream(scan_id):
    """
    SSE endpoint — streams progress events for a running scan.
    Each event is a JSON object: {phase, status, message}.
    Closes automatically when phase=='complete' or after a 3-minute timeout.
    """
    @stream_with_context
    def generate():
        seen     = 0
        deadline = _time.time() + 180  # 3-minute hard timeout
        while _time.time() < deadline:
            events = _progress.get(scan_id, [])
            while seen < len(events):
                evt = events[seen]
                yield f"data: {json.dumps(evt)}\n\n"
                seen += 1
                if evt.get("phase") == "complete":
                    return
            _time.sleep(0.3)
        yield f"data: {json.dumps({'phase':'complete','status':'error','message':'Scan timed out'})}\n\n"

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "X-Accel-Buffering": "no",   # disable nginx buffering if behind a proxy
            "Connection":        "keep-alive",
        }
    )


@app.route("/api/status", methods=["GET"])
def check_status():
    return jsonify({
        "docker_available": is_docker_available(),
        "pdf_available": pdf_available
    })

if __name__ == "__main__":
    init_db()
    # Find active port or fallback to 5001
    app.run(host="0.0.0.0", port=5001, debug=True)


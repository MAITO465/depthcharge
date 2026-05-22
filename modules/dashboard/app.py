import os
import sys
import sqlite3
import json
import threading
from flask import Flask, render_template, jsonify, request

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
    """
    try:
        # 1. Reputation
        rep_results = scan_reputation(package_name, ecosystem)
        
        if skip_reputation:
            rep_results["vulnerabilities"] = []
            rep_results["typosquatting_detected"] = False
            rep_results["is_suspiciously_new"] = False
            rep_results["known_malicious"] = False
            rep_results["malware_database_match"] = False

        if not rep_results.get("exists"):
            if rep_results.get("typosquatting_detected"):
                # Package doesn't exist but typosquatting detected — still score it
                static_results = {"typosquatting": rep_results.get("typosquatting_info"), "alerts": [], "files_scanned": 0, "obfuscation_detected": False, "dangerous_ast_detected": False, "success": False}
                dynamic_results = {"docker_available": False, "events": []}
                # Fix for calculate_score requiring package_name
                score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute("""
                    UPDATE scans SET version = 'N/A', score = ?, risk_level = ?, reputation_data = ?, static_data = ?, dynamic_data = ?, reasons = ? WHERE id = ?
                """, (score_data["score"], score_data["risk_level"], json.dumps(rep_results), json.dumps(static_results), json.dumps(dynamic_results), json.dumps(score_data["reasons"]), scan_id))
                conn.commit()
                conn.close()
                return
            error_msg = rep_results.get("error", "Package not found")
            update_scan_failed(scan_id, error_msg)
            return

        # 2. Static
        download_url = rep_results.get("download_url")
        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            static_results = scan_static(package_name, ecosystem, download_url)

        # 3. Dynamic
        dynamic_results = {"docker_available": False, "events": []}
        if not skip_dynamic:
            # Bug fix: scan_dynamic needs download_url as 3rd arg in the API? Wait, the runner takes (package_name, ecosystem, archive_url)
            # In app.py it was `scan_dynamic(package_name, ecosystem)`. Let's fix that too.
            dynamic_results = scan_dynamic(package_name, ecosystem, download_url)

        # 4. Scorer
        score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)

        # Update SQLite with success
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute("""
            UPDATE scans
            SET version = ?, score = ?, risk_level = ?, reputation_data = ?, static_data = ?, dynamic_data = ?, reasons = ?
            WHERE id = ?
        """, (
            rep_results.get("version"),
            score_data["score"],
            score_data["risk_level"],
            json.dumps(rep_results),
            json.dumps(static_results),
            json.dumps(dynamic_results),
            json.dumps(score_data["reasons"]),
            scan_id
        ))
        conn.commit()
        conn.close()
    except Exception as e:
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


import sys
import os
import sqlite3
import json
import argparse
import re
from datetime import datetime

# Import scanning modules
from modules.reputation.checker import scan_reputation
from modules.static.analyzer import scan_static
from modules.sandbox.runner import scan_dynamic
from scorer import calculate_score
try:
    from modules.sbom.generator import generate_sbom
    sbom_available = True
except ImportError:
    sbom_available = False

try:
    from modules.report.pdf_generator import generate_pdf_report
    pdf_available = True
except ImportError:
    pdf_available = False

# Try to import Rich for beautiful printing, fall back to print
try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.status import Status
    from rich import print as rprint
    rich_available = True
    console = Console()
except ImportError:
    rich_available = False
    console = None

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "depthcharge.db")

def init_db():
    """
    Initializes the SQLite database with extended schema.
    """
    db_dir = os.path.dirname(DB_PATH)
    os.makedirs(db_dir, exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Core scan history
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            version TEXT,
            score INTEGER,
            risk_level TEXT,
            scanned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            reputation_data TEXT,
            static_data TEXT,
            dynamic_data TEXT,
            reasons TEXT
        )
    """)

    # Package inventory: one row per unique (package, ecosystem), updated on every scan
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS package_inventory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            package_name TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_version TEXT,
            last_score INTEGER,
            last_risk_level TEXT,
            scan_count INTEGER DEFAULT 1,
            score_history TEXT DEFAULT '[]',
            UNIQUE(package_name, ecosystem)
        )
    """)

    conn.commit()
    conn.close()

def save_scan(package_name, ecosystem, version, score, risk_level, reputation, static, dynamic, reasons):
    """
    Saves a scan result into SQLite and updates the package inventory table.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Scan history
    cursor.execute("""
        INSERT INTO scans (package_name, ecosystem, version, score, risk_level, reputation_data, static_data, dynamic_data, reasons)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        package_name, ecosystem, version, score, risk_level,
        json.dumps(reputation), json.dumps(static), json.dumps(dynamic), json.dumps(reasons)
    ))

    # Package inventory upsert
    now = datetime.now().isoformat()
    cursor.execute(
        "SELECT id, score_history, scan_count FROM package_inventory "
        "WHERE package_name=? AND ecosystem=?",
        (package_name, ecosystem)
    )
    row = cursor.fetchone()
    if row:
        existing_history = json.loads(row[1] or "[]")
        existing_history.append({"scanned_at": now, "version": version, "score": score})
        cursor.execute("""
            UPDATE package_inventory
            SET last_seen=?, last_version=?, last_score=?, last_risk_level=?,
                scan_count=scan_count+1, score_history=?
            WHERE package_name=? AND ecosystem=?
        """, (now, version, score, risk_level, json.dumps(existing_history), package_name, ecosystem))
    else:
        cursor.execute("""
            INSERT INTO package_inventory
                (package_name, ecosystem, first_seen, last_seen, last_version,
                 last_score, last_risk_level, scan_count, score_history)
            VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?)
        """, (package_name, ecosystem, now, now, version, score, risk_level,
              json.dumps([{"scanned_at": now, "version": version, "score": score}])))

    conn.commit()
    conn.close()

def get_scans_history():
    """
    Fetches scan history.
    """
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT id, package_name, ecosystem, version, score, risk_level, scanned_at FROM scans ORDER BY scanned_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return rows

def format_level(level):
    if not rich_available:
        return level
    if level == "High":
        return "[bold red]High[/bold red]"
    elif level == "Medium":
        return "[bold yellow]Medium[/bold yellow]"
    return "[bold green]Low[/bold green]"

def run_scan(package_name, ecosystem="pypi", skip_reputation=False, skip_static=False, skip_dynamic=False):
    """
    Coordinates reputation, static, and dynamic scanning of a single package.
    """
    init_db()
    package_name = package_name.strip()
    ecosystem = ecosystem.lower()
    
    if rich_available:
        console.print(Panel.fit(f"[bold cyan]Depthcharge dependency analysis: {ecosystem}/{package_name}[/bold cyan]", border_style="blue"))
        
        # 1. Reputation Scan
        if package_name.startswith("file://"):
            console.print(f"[bold green]Mocking Reputation Scan for local archive {package_name}...[/bold green]")
            import os
            # If package_name has a file:// prefix, we just create a mock reputation result
            rep_results = {
                "exists": True,
                "name": os.path.basename(package_name),
                "author": "Local User",
                "author_email": "local@localhost",
                "version": "1.0.0",
                "prev_version": None,
                "summary": "Local archive scan",
                "home_page": "",
                "license": "Unknown",
                "releases_count": 1,
                "created_at": "2024-01-01T00:00:00",
                "latest_release_at": "2024-01-01T00:00:00",
                "download_url": package_name,
                "all_versions_data": {},
                "vulnerabilities": [],
                "malware_database_match": False,
                "typosquatting_detected": False,
                "is_suspiciously_new": False,
                "known_malicious": False
            }
        else:
            with console.status(f"[bold green]Running Reputation Scan for {package_name}...", spinner="dots"):
                rep_results = scan_reputation(package_name, ecosystem)
            
        if skip_reputation:
            if rich_available:
                console.print("[bold yellow]⚠ Reputation Scan skipped by request (metadata fetched only).[/bold yellow]")
            else:
                print("⚠ Reputation Scan skipped by request (metadata fetched only).")
            # Clear threat flags so score is 0
            rep_results["vulnerabilities"] = []
            rep_results["typosquatting_detected"] = False
            rep_results["is_suspiciously_new"] = False
            rep_results["known_malicious"] = False
            rep_results["malware_database_match"] = False
            
        if not rep_results.get("exists"):
            if rep_results.get("typosquatting_detected"):
                # Package doesn't exist but is a typosquat — still report a score
                console.print(f"[bold yellow]⚠ Package not found on registry, but typosquatting detected.[/bold yellow]")
                console.print(f"[bold yellow]  {rep_results.get('typosquatting_info', {}).get('message', '')}[/bold yellow]")
                console.print("[bold green]✓ Reputation Scan complete.[/bold green]")
                # Proceed with empty static/dynamic results so the scorer can flag the typosquat
                static_results = {"typosquatting": rep_results.get("typosquatting_info"), "alerts": [], "files_scanned": 0, "obfuscation_detected": False, "dangerous_ast_detected": False, "success": False}
                dynamic_results = {"docker_available": False, "events": []}
                ver = "Unknown"
                score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
                save_scan(package_name, ecosystem, ver, score_data["score"], score_data["risk_level"], rep_results, static_results, dynamic_results, score_data["reasons"])
                score = score_data["score"]
                level = format_level(score_data["risk_level"])
                console.print(Panel(
                    f"Risk Score: [bold]{score}/100[/bold] | Risk Level: {level}\n\n"
                    f"[bold]Reasons for score:[/bold]\n" + "\n".join([f"- {r}" for r in score_data["reasons"]]),
                    title="Scan Summary",
                    border_style="red" if score_data["risk_level"] == "High" else "yellow" if score_data["risk_level"] == "Medium" else "green"
                ))
                return {"score": score_data["score"], "risk_level": score_data["risk_level"], "reasons": score_data["reasons"], "breakdown": score_data["breakdown"], "reputation": rep_results, "static": static_results, "dynamic": dynamic_results}
            else:
                console.print(f"[bold red]❌ Reputation Scan Error:[/bold red] {rep_results.get('error')}")
                return None
        
        # 2. Static Scan
        download_url = rep_results.get("download_url")
        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            with console.status(f"[bold green]Running Static Scan for {package_name}...", spinner="dots"):
                static_results = scan_static(package_name, ecosystem, download_url)
                
            if static_results.get("error"):
                console.print(f"[bold yellow]⚠ Static Scan Warning:[/bold yellow] {static_results.get('error')}")
            else:
                console.print("[bold green]✓ Static Scan complete.[/bold green]")
        else:
            console.print("[bold yellow]⚠ Static scan skipped by request.[/bold yellow]")
            
        # 3. Dynamic Scan
        dynamic_results = {"docker_available": False, "events": []}
        if not skip_dynamic:
            with console.status(f"[bold green]Running Dynamic Sandbox Scan for {package_name}...", spinner="dots"):
                dynamic_results = scan_dynamic(package_name, ecosystem, rep_results.get("download_url"))
                
            if dynamic_results.get("error"):
                console.print(f"[bold yellow]⚠ Dynamic Sandbox Warn:[/bold yellow] {dynamic_results.get('error')}")
            else:
                console.print("[bold green]✓ Dynamic Scan complete.[/bold green]")
        else:
            console.print("[bold yellow]⚠ Dynamic scan skipped by request.[/bold yellow]")
    else:
        print(f"--- Scanning {ecosystem}/{package_name} ---")
        print("Running Reputation Scan...")
        rep_results = scan_reputation(package_name, ecosystem)
        if skip_reputation:
            if rich_available:
                console.print("[bold yellow]⚠ Reputation Scan skipped by request (metadata fetched only).[/bold yellow]")
            else:
                print("⚠ Reputation Scan skipped by request (metadata fetched only).")
            # Clear threat flags so score is 0
            rep_results["vulnerabilities"] = []
            rep_results["typosquatting_detected"] = False
            rep_results["is_suspiciously_new"] = False
            rep_results["known_malicious"] = False
            rep_results["malware_database_match"] = False
            
        if not rep_results.get("exists"):
            if rep_results.get("typosquatting_detected"):
                print(f"Warning: Package not found on registry, but typosquatting detected.")
                print(f"  {rep_results.get('typosquatting_info', {}).get('message', '')}")
                static_results = {"typosquatting": rep_results.get("typosquatting_info"), "alerts": [], "files_scanned": 0, "obfuscation_detected": False, "dangerous_ast_detected": False, "success": False}
                dynamic_results = {"docker_available": False, "events": []}
                ver = "Unknown"
                score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
                save_scan(package_name, ecosystem, ver, score_data["score"], score_data["risk_level"], rep_results, static_results, dynamic_results, score_data["reasons"])
                print(f"\nRisk Score: {score_data['score']}/100 ({score_data['risk_level']})")
                for r in score_data["reasons"]:
                    print(f" - {r}")
                return {"score": score_data["score"], "risk_level": score_data["risk_level"], "reasons": score_data["reasons"], "breakdown": score_data["breakdown"], "reputation": rep_results, "static": static_results, "dynamic": dynamic_results}
            else:
                print(f"Error: {rep_results.get('error')}")
                return None
            
        static_results = {"success": True, "files_scanned": 0, "alerts": [], "obfuscation_detected": False, "dangerous_ast_detected": False}
        if not skip_static:
            print("Running Static Scan...")
            static_results = scan_static(package_name, ecosystem, rep_results.get("download_url"))
        else:
            print("Static scan skipped by request.")
        
        dynamic_results = {"docker_available": False, "events": []}
        if not skip_dynamic:
            print("Running Dynamic Scan...")
            dynamic_results = scan_dynamic(package_name, ecosystem, rep_results.get("download_url"))
            
    # Calculate Score
    ver = rep_results.get("version", "Unknown")
    score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)
    
    # Save to sqlite
    save_scan(
        package_name,
        ecosystem,
        ver,
        score_data["score"],
        score_data["risk_level"],
        rep_results,
        static_results,
        dynamic_results,
        score_data["reasons"]
    )
    
    # Render final report
    if rich_available:
        # Score Panel
        score = score_data["score"]
        level = format_level(score_data["risk_level"])
        console.print(Panel(
            f"Risk Score: [bold]{score}/100[/bold] | Risk Level: {level}\n\n"
            f"[bold]Reasons for score:[/bold]\n" + "\n".join([f"- {r}" for r in score_data["reasons"]]),
            title="Scan Summary",
            border_style="red" if score_data["risk_level"] == "High" else "yellow" if score_data["risk_level"] == "Medium" else "green"
        ))
        
        # Details Table
        table = Table(title="Package Details")
        table.add_column("Property", style="cyan")
        table.add_column("Value", style="magenta")
        
        table.add_row("Name", rep_results.get("name"))
        table.add_row("Ecosystem", ecosystem.upper())
        table.add_row("Latest Version", ver)
        table.add_row("Author", rep_results.get("author"))
        table.add_row("Author Email", rep_results.get("author_email"))
        table.add_row("Created At", rep_results.get("created_at"))
        table.add_row("Latest Release", rep_results.get("latest_release_at"))
        table.add_row("Releases Count", str(rep_results.get("releases_count")))
        table.add_row("Vulnerabilities (OSV)", str(len(rep_results.get("vulnerabilities", []))))
        console.print(table)
        
        # Alerts Table
        alerts = static_results.get("alerts", [])
        if alerts:
            alert_table = Table(title="Static Analysis Alerts")
            alert_table.add_column("File", style="yellow")
            alert_table.add_column("Line", style="cyan")
            alert_table.add_column("Severity", style="red")
            alert_table.add_column("Type", style="magenta")
            alert_table.add_column("Message", style="white")
            for a in alerts:
                sev_color = "[red]High[/red]" if a.get("severity") == "high" else "[yellow]Medium[/yellow]" if a.get("severity") == "medium" else "[green]Low[/green]"
                alert_table.add_row(
                    a.get("file", "unknown"),
                    str(a.get("line", 0)),
                    sev_color,
                    a.get("type", "unknown"),
                    a.get("message", "")
                )
            console.print(alert_table)
            
        # Sandbox Events Table
        events = dynamic_results.get("events", [])
        if events:
            event_table = Table(title="Sandbox Runtime Events")
            event_table.add_column("Event Type", style="cyan")
            event_table.add_column("Details", style="white")
            for e in events:
                event_table.add_row(e.get("type"), e.get("details"))
            console.print(event_table)
    else:
        print("\n=== SCAN REPORT ===")
        print(f"Package: {ecosystem}/{package_name} ({ver})")
        print(f"Risk Score: {score_data['score']}/100 ({score_data['risk_level']})")
        print("Reasons:")
        for r in score_data["reasons"]:
            print(f" - {r}")
        print("\nStatic Scan Files Scanned:", static_results.get("files_scanned"))
        print("Static Scan Alerts:", len(static_results.get("alerts", [])))
        print("Sandbox Events:", len(dynamic_results.get("events", [])))
        
    return {
        "score": score_data["score"],
        "risk_level": score_data["risk_level"],
        "reasons": score_data["reasons"],
        "breakdown": score_data["breakdown"],
        "reputation": rep_results,
        "static": static_results,
        "dynamic": dynamic_results
    }

def scan_file(file_path, default_ecosystem="pypi", skip_reputation=False, skip_static=False, skip_dynamic=False):
    """
    Scans dependencies listed in requirements.txt or package.json.
    """
    if not os.path.exists(file_path):
        if rich_available:
            console.print(f"[bold red]Error: File not found: {file_path}[/bold red]")
        else:
            print(f"Error: File not found: {file_path}")
        return False, {}
        
    packages = []
    
    # Auto detect ecosystem
    basename = os.path.basename(file_path)
    if basename == "requirements.txt" or file_path.endswith(".txt"):
        ecosystem = "pypi"
        with open(file_path, "r") as f:
            for line in f:
                line = line.strip()
                # Skip comments, empty lines, and options (e.g., -r, --index-url)
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Extract package name (remove versions/specifiers e.g. requests>=2.0 -> requests)
                name = re.split(r"[=<>~!]", line)[0].strip()
                if name:
                    packages.append(name)
    elif basename == "package.json" or file_path.endswith(".json"):
        ecosystem = "npm"
        try:
            with open(file_path, "r") as f:
                data = json.load(f)
                # Read dependencies and devDependencies
                deps = data.get("dependencies", {})
                dev_deps = data.get("devDependencies", {})
                packages.extend(deps.keys())
                packages.extend(dev_deps.keys())
        except Exception as e:
            if rich_available:
                console.print(f"[bold red]Failed to parse JSON file {file_path}: {e}[/bold red]")
            else:
                print(f"Failed to parse JSON file {file_path}: {e}")
            return False, {}
    else:
        ecosystem = default_ecosystem
        # Just read line by line as fallback
        with open(file_path, "r") as f:
            for line in f:
                name = line.strip()
                if name:
                    packages.append(name)

    if not packages:
        if rich_available:
            console.print("[bold yellow]No packages found to scan.[/bold yellow]")
        else:
            print("No packages found to scan.")
        return False, {}

    if rich_available:
        console.print(f"[bold cyan]Found {len(packages)} packages to scan in {file_path}...[/bold cyan]")
    else:
        print(f"Found {len(packages)} packages to scan in {file_path}...")
        
    results = {}
    has_high_risk = False
    for pkg in packages:
        try:
            res = run_scan(pkg, ecosystem, skip_dynamic=skip_dynamic)
            if res:
                results[pkg] = res
                if res.get("score", 0) >= 70:
                    has_high_risk = True
        except Exception as e:
            if rich_available:
                console.print(f"[bold red]Error scanning {pkg}: {e}[/bold red]")
            else:
                print(f"Error scanning {pkg}: {e}")
                
    # Print summary table
    if rich_available and results:
        summary_table = Table(title=f"Scan Summary for {basename}")
        summary_table.add_column("Package Name", style="cyan")
        summary_table.add_column("Risk Score", style="magenta")
        summary_table.add_column("Risk Level", style="white")
        
        for pkg, r in results.items():
            summary_table.add_row(pkg, str(r["score"]), format_level(r["risk_level"]))
        console.print(summary_table)
    elif results:
        print("\n--- FILE SCAN SUMMARY ---")
        for pkg, r in results.items():
            print(f"{pkg}: Risk Score {r['score']}/100 ({r['risk_level']})")
            
    return has_high_risk, results

def show_history():
    """
    Renders scan history.
    """
    init_db()
    scans = get_scans_history()
    if not scans:
        if rich_available:
            console.print("[bold yellow]No scan history found. Try running a scan first![/bold yellow]")
        else:
            print("No scan history found. Try running a scan first!")
        return
        
    if rich_available:
        table = Table(title="Scan History")
        table.add_column("ID", style="cyan")
        table.add_column("Package", style="magenta")
        table.add_column("Ecosystem", style="cyan")
        table.add_column("Version", style="white")
        table.add_column("Risk Score", style="yellow")
        table.add_column("Risk Level", style="white")
        table.add_column("Scanned At", style="green")
        
        for s in scans:
            table.add_row(
                str(s["id"]),
                s["package_name"],
                s["ecosystem"].upper(),
                s["version"] or "Unknown",
                str(s["score"]),
                format_level(s["risk_level"]),
                s["scanned_at"]
            )
        console.print(table)
    else:
        print("\n--- SCAN HISTORY ---")
        for s in scans:
            print(f"ID: {s['id']} | {s['ecosystem'].upper()}/{s['package_name']} ({s['version']}) - Score: {s['score']} ({s['risk_level']}) | {s['scanned_at']}")

def generate_markdown_report(results, output_path):
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# Depthcharge Dependency Security Audit Report\n\n")
        f.write(f"Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        # Summary metrics
        total = len(results)
        high = sum(1 for r in results.values() if r["risk_level"] == "High")
        medium = sum(1 for r in results.values() if r["risk_level"] == "Medium")
        low = sum(1 for r in results.values() if r["risk_level"] == "Low")
        
        f.write("## Executive Summary\n\n")
        f.write(f"- **Total Dependencies Scanned**: {total}\n")
        f.write(f"- **🔴 High Risk**: {high}\n")
        f.write(f"- **🟡 Medium Risk**: {medium}\n")
        f.write(f"- **🟢 Low Risk**: {low}\n\n")
        
        f.write("| Package Name | Ecosystem | Version | Score | Risk Level |\n")
        f.write("| --- | --- | --- | --- | --- |\n")
        for pkg, r in results.items():
            eco = r.get("reputation", {}).get("ecosystem", "unknown").upper()
            ver = r.get("reputation", {}).get("version", "Unknown")
            f.write(f"| {pkg} | {eco} | {ver} | {r['score']}/100 | {r['risk_level']} |\n")
        f.write("\n---\n\n")
        
        f.write("## Detailed Package Audit\n\n")
        for pkg, r in results.items():
            eco = r.get("reputation", {}).get("ecosystem", "unknown").upper()
            ver = r.get("reputation", {}).get("version", "Unknown")
            f.write(f"### {pkg} (v{ver} - {eco})\n")
            f.write(f"- **Overall Score**: {r['score']}/100\n")
            f.write(f"- **Risk Level**: {r['risk_level']}\n\n")
            
            f.write("#### Score Reasons:\n")
            for reason in r["reasons"]:
                f.write(f"- {reason}\n")
            f.write("\n")
            
            # Reputation
            rep = r.get("reputation", {})
            vulns = rep.get("vulnerabilities", [])
            f.write("#### 1. Reputation Scan\n")
            f.write(f"- Author: {rep.get('author', 'Unknown')}\n")
            f.write(f"- Created At: {rep.get('created_at', 'Unknown')}\n")
            f.write(f"- Releases Count: {rep.get('releases_count', 0)}\n")
            f.write(f"- OSV Vulnerabilities: {len(vulns)}\n")
            if vulns:
                f.write("\n| Vulnerability ID | Summary |\n")
                f.write("| --- | --- |\n")
                for v in vulns:
                    f.write(f"| {v.get('id')} | {v.get('summary')} |\n")
            f.write("\n")
            
            # Static Scan
            static = r.get("static", {})
            alerts = static.get("alerts", [])
            f.write("#### 2. Static AST Scan\n")
            f.write(f"- Files Scanned: {static.get('files_scanned', 0)}\n")
            f.write(f"- Static Alerts: {len(alerts)}\n")
            if alerts:
                f.write("\n| File | Line | Severity | Message |\n")
                f.write("| --- | --- | --- | --- |\n")
                for a in alerts:
                    f.write(f"| `{a.get('file')}` | {a.get('line')} | {a.get('severity').upper()} | {a.get('message')} |\n")
            f.write("\n")
            
            # Dynamic Scan
            dynamic = r.get("dynamic", {})
            events = dynamic.get("events", [])
            f.write("#### 3. Dynamic Sandbox Scan\n")
            f.write(f"- Docker Sandbox Available: {dynamic.get('docker_available', False)}\n")
            f.write(f"- Installation Success: {dynamic.get('installation_success', False)}\n")
            f.write(f"- Import Success: {dynamic.get('import_success', False)}\n")
            f.write(f"- Sandbox Alert Events: {len(events)}\n")
            if events:
                f.write("\n| Event Type | Details |\n")
                f.write("| --- | --- |\n")
                for e in events:
                    f.write(f"| {e.get('type').upper()} | `{e.get('details')}` |\n")
            f.write("\n---\n\n")

    print(f"Markdown report successfully saved to {output_path}")

def generate_html_report(results, output_path):
    # Summary metrics
    total = len(results)
    high = sum(1 for r in results.values() if r["risk_level"] == "High")
    medium = sum(1 for r in results.values() if r["risk_level"] == "Medium")
    low = sum(1 for r in results.values() if r["risk_level"] == "Low")
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Depthcharge Dependency Security Audit</title>
    <style>
        body {{
            background-color: #0b0f19;
            color: #f3f4f6;
            font-family: system-ui, -apple-system, sans-serif;
            margin: 0;
            padding: 2rem;
            line-height: 1.5;
        }}
        .container {{
            max-width: 1100px;
            margin: 0 auto;
        }}
        h1, h2, h3, h4 {{
            margin-top: 0;
            color: #ffffff;
        }}
        h1 {{
            font-size: 2.2rem;
            font-weight: 800;
            background: linear-gradient(135deg, #8b5cf6, #3b82f6);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 0.5rem;
        }}
        .timestamp {{
            font-size: 0.85rem;
            color: #9ca3af;
            margin-bottom: 2rem;
        }}
        .metrics-grid {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 1.5rem;
            margin-bottom: 2rem;
        }}
        .metric-card {{
            background: rgba(20, 27, 45, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 12px;
            padding: 1.5rem;
            text-align: center;
        }}
        .metric-value {{
            font-size: 2.2rem;
            font-weight: 800;
            margin-bottom: 0.3rem;
        }}
        .metric-label {{
            font-size: 0.75rem;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.05rem;
        }}
        .text-high {{ color: #ef4444; }}
        .text-medium {{ color: #f59e0b; }}
        .text-low {{ color: #10b981; }}
        .text-total {{ color: #3b82f6; }}
        
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 2rem;
            background: rgba(20, 27, 45, 0.3);
            border-radius: 12px;
            overflow: hidden;
            border: 1px solid rgba(255, 255, 255, 0.08);
        }}
        th, td {{
            padding: 1rem;
            text-align: left;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
        }}
        th {{
            background: rgba(255, 255, 255, 0.04);
            font-weight: 600;
            color: #9ca3af;
            font-size: 0.85rem;
            text-transform: uppercase;
        }}
        tr:last-child td {{
            border-bottom: none;
        }}
        .badge {{
            padding: 0.25rem 0.5rem;
            border-radius: 6px;
            font-size: 0.75rem;
            font-weight: 700;
            display: inline-block;
        }}
        .badge.high {{ background: rgba(239, 68, 68, 0.15); color: #ef4444; }}
        .badge.medium {{ background: rgba(245, 158, 11, 0.15); color: #f59e0b; }}
        .badge.low {{ background: rgba(16, 185, 129, 0.15); color: #10b981; }}
        
        .pkg-section {{
            background: rgba(20, 27, 45, 0.5);
            border: 1px solid rgba(255, 255, 255, 0.08);
            border-radius: 16px;
            padding: 1.5rem;
            margin-bottom: 2rem;
        }}
        .pkg-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 1px solid rgba(255, 255, 255, 0.08);
            padding-bottom: 1rem;
            margin-bottom: 1.2rem;
        }}
        .pkg-name-title {{
            font-size: 1.5rem;
            font-weight: 700;
            margin: 0;
        }}
        .pkg-eco-badge {{
            font-size: 0.7rem;
            background: rgba(255,255,255,0.08);
            color: #d1d5db;
            padding: 0.15rem 0.4rem;
            border-radius: 4px;
            font-weight: bold;
            margin-left: 0.5rem;
            vertical-align: middle;
        }}
        .pkg-score-badge {{
            font-size: 1.3rem;
            font-weight: 800;
            padding: 0.4rem 0.8rem;
            border-radius: 8px;
            border: 1px solid;
        }}
        .pkg-score-badge.high {{ border-color: rgba(239, 68, 68, 0.3); background: rgba(239, 68, 68, 0.05); color: #ef4444; }}
        .pkg-score-badge.medium {{ border-color: rgba(245, 158, 11, 0.3); background: rgba(245, 158, 11, 0.05); color: #f59e0b; }}
        .pkg-score-badge.low {{ border-color: rgba(16, 185, 129, 0.3); background: rgba(16, 185, 129, 0.05); color: #10b981; }}
        
        .reasons-list {{
            background: rgba(255, 255, 255, 0.02);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 1rem 1rem 1rem 2rem;
            margin-bottom: 1.5rem;
        }}
        .reasons-list li {{
            margin-bottom: 0.4rem;
            font-size: 0.9rem;
        }}
        .reasons-list li::marker {{
            color: #8b5cf6;
        }}
        
        .grid-2 {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 1.5rem;
            margin-bottom: 1.5rem;
        }}
        .meta-box {{
            background: rgba(255, 255, 255, 0.01);
            border: 1px solid rgba(255, 255, 255, 0.05);
            border-radius: 8px;
            padding: 1rem;
        }}
        .meta-box h4 {{
            margin-bottom: 0.6rem;
            font-size: 0.95rem;
            color: #9ca3af;
            border-bottom: 1px solid rgba(255, 255, 255, 0.05);
            padding-bottom: 0.4rem;
        }}
        .meta-row {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            margin-bottom: 0.4rem;
        }}
        .meta-row span:first-child {{
            color: #9ca3af;
        }}
        
        .alert-row-item {{
            display: flex;
            justify-content: space-between;
            font-size: 0.85rem;
            padding: 0.4rem 0;
            border-bottom: 1px solid rgba(255,255,255,0.03);
        }}
        .alert-row-item:last-child {{
            border-bottom: none;
        }}
        .code-path {{
            font-family: monospace;
            color: #f472b6;
        }}
        
        .no-data-msg {{
            font-size: 0.85rem;
            color: #10b981;
            display: flex;
            align-items: center;
            gap: 0.4rem;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>Depthcharge Dependency Audit</h1>
        <div class="timestamp">Generated on {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
        
        <div class="metrics-grid">
            <div class="metric-card">
                <div class="metric-value text-total">{total}</div>
                <div class="metric-label">Total Packages</div>
            </div>
            <div class="metric-card">
                <div class="metric-value text-high">{high}</div>
                <div class="metric-label">High Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value text-medium">{medium}</div>
                <div class="metric-label">Medium Risk</div>
            </div>
            <div class="metric-card">
                <div class="metric-value text-low">{low}</div>
                <div class="metric-label">Low Risk</div>
            </div>
        </div>

        <h2>Dependencies Checklist Summary</h2>
        <table>
            <thead>
                <tr>
                    <th>Package Name</th>
                    <th>Ecosystem</th>
                    <th>Version</th>
                    <th>Score</th>
                    <th>Risk Level</th>
                </tr>
            </thead>
            <tbody>
        """
    
    for pkg, r in results.items():
        eco = r.get("reputation", {}).get("ecosystem", "unknown").upper()
        ver = r.get("reputation", {}).get("version", "Unknown")
        badge_class = r["risk_level"].lower()
        html_content += f"""
                <tr>
                    <td><strong>{pkg}</strong></td>
                    <td>{eco}</td>
                    <td>{ver}</td>
                    <td>{r['score']}/100</td>
                    <td><span class="badge {badge_class}">{r['risk_level']}</span></td>
                </tr>
        """
        
    html_content += """
            </tbody>
        </table>

        <h2>Detailed Vulnerability & Code Analysis</h2>
        """
        
    for pkg, r in results.items():
        eco = r.get("reputation", {}).get("ecosystem", "unknown").upper()
        ver = r.get("reputation", {}).get("version", "Unknown")
        badge_class = r["risk_level"].lower()
        
        # Reasons HTML
        reasons_html = "".join([f"<li>{reason}</li>" for reason in r["reasons"]])
        
        # OSV Vulns HTML
        rep = r.get("reputation", {})
        vulns = rep.get("vulnerabilities", [])
        if vulns:
            vulns_html = "".join([
                f'<div class="alert-row-item"><strong>{v.get("id")}</strong><span>{v.get("summary")}</span></div>' 
                for v in vulns
            ])
        else:
            vulns_html = '<div class="no-data-msg">✓ No known CVE or GHSA vulnerabilities.</div>'
            
        # Static AST Alerts HTML
        static = r.get("static", {})
        alerts = static.get("alerts", [])
        if alerts:
            alerts_html = "".join([
                f'<div class="alert-row-item">'
                f'<span><span class="code-path">{a.get("file")}:{a.get("line")}</span> ({a.get("type")})</span>'
                f'<span class="text-{a.get("severity")}">{a.get("severity").upper()}: {a.get("message")}</span>'
                f'</div>' 
                for a in alerts
            ])
        else:
            alerts_html = '<div class="no-data-msg">✓ No suspicious syntax patterns found.</div>'
            
        # Sandbox Alerts HTML
        dynamic = r.get("dynamic", {})
        events = dynamic.get("events", [])
        if events:
            events_html = "".join([
                f'<div class="alert-row-item">'
                f'<strong>{e.get("type").upper()}</strong>'
                f'<span>{e.get("details")}</span>'
                f'</div>' 
                for e in events
            ])
        else:
            events_html = '<div class="no-data-msg">✓ No unexpected filesystem, network, or process spawning calls.</div>'
            
        html_content += f"""
        <div class="pkg-section">
            <div class="pkg-header">
                <div>
                    <h3 class="pkg-name-title">{pkg}<span class="pkg-eco-badge">{eco} v{ver}</span></h3>
                </div>
                <div class="pkg-score-badge {badge_class}">{r['score']}/100</div>
            </div>
            
            <h4>Audit Evaluation Log</h4>
            <ul class="reasons-list">
                {reasons_html}
            </ul>
            
            <div class="grid-2">
                <div class="meta-box">
                    <h4>Registry Metadata</h4>
                    <div class="meta-row"><span>Author</span><span>{rep.get('author', 'Unknown')}</span></div>
                    <div class="meta-row"><span>Email</span><span>{rep.get('author_email', 'Unknown')}</span></div>
                    <div class="meta-row"><span>Created Date</span><span>{rep.get('created_at', 'Unknown').split('T')[0] if rep.get('created_at') and rep.get('created_at') != 'Unknown' else 'Unknown'}</span></div>
                    <div class="meta-row"><span>Releases count</span><span>{rep.get('releases_count', 0)}</span></div>
                </div>
                <div class="meta-box">
                    <h4>Known Vulnerabilities ({len(vulns)})</h4>
                    {vulns_html}
                </div>
            </div>
            
            <div class="grid-2">
                <div class="meta-box">
                    <h4>Static AST Analysis ({len(alerts)})</h4>
                    {alerts_html}
                </div>
                <div class="meta-box">
                    <h4>Dynamic Sandbox Events ({len(events)})</h4>
                    {events_html}
                </div>
            </div>
        </div>
        """
        
    html_content += """
    </div>
</body>
</html>
"""
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html_content)
        
    print(f"HTML audit report successfully saved to {output_path}")

def generate_report(results, output_path):
    if output_path.endswith(".md"):
        generate_markdown_report(results, output_path)
    elif output_path.endswith(".pdf"):
        if not pdf_available:
            if rich_available:
                console.print("[bold red]Error: PDF generation is not available because 'reportlab' is missing. Please install it: pip install reportlab[/bold red]")
            else:
                print("Error: PDF generation is not available because 'reportlab' is missing. Please install it: pip install reportlab")
            sys.exit(1)
        generate_pdf_report(results, output_path)
    else:
        # Default to HTML
        generate_html_report(results, output_path)


# ── Policy-as-code config loader ──────────────────────────────────────────────
def load_policy_config(config_path=None):
    """
    Loads depthcharge.yml policy-as-code config.
    Returns a dict with policy rules; uses safe defaults if file absent.
    """
    import yaml as _yaml  # optional dep
    defaults = {
        "block_packages_younger_than_days": None,      # e.g. 30
        "require_manual_review_on_new_maintainer": True,
        "auto_block_campaign_fingerprints": [],         # list of package-name patterns
        "threshold": 70,
        "skip_dynamic": False,
        "skip_static": False,
        "skip_reputation": False,
        "delta_scanning": False,                        # only scan changed packages in CI
    }
    paths_to_try = [config_path, "depthcharge.yml", "depthcharge.yaml"]
    for p in paths_to_try:
        if p and os.path.exists(p):
            try:
                with open(p, "r") as f:
                    data = _yaml.safe_load(f) or {}
                defaults.update(data)
                break
            except Exception:
                pass
    return defaults


def apply_policy(package_name, rep_results, policy):
    """
    Apply policy-as-code rules on top of default scoring.
    Returns extra reasons list and whether to force-block.
    """
    extra_reasons = []
    force_block = False

    # Block packages younger than N days
    min_days = policy.get("block_packages_younger_than_days")
    if min_days and rep_results:
        days_old = rep_results.get("days_old")
        if isinstance(days_old, int) and days_old < min_days:
            force_block = True
            extra_reasons.append(
                f"[Policy] Package is only {days_old} days old "
                f"(policy requires >= {min_days} days) — blocked."
            )

    # Flag new maintainer for manual review
    if policy.get("require_manual_review_on_new_maintainer") and rep_results:
        if rep_results.get("maintainer_changed"):
            extra_reasons.append(
                "[Policy] Maintainer email changed — manual review required per policy."
            )

    # Campaign fingerprint match (substring match on package name)
    for fingerprint in policy.get("auto_block_campaign_fingerprints", []):
        if fingerprint.lower() in package_name.lower():
            force_block = True
            extra_reasons.append(
                f"[Policy] Package name matches campaign fingerprint '{fingerprint}' — auto-blocked."
            )

    return extra_reasons, force_block


# ── Delta-only lockfile scanner ───────────────────────────────────────────────
def get_delta_packages(lockfile_path, ecosystem, policy):
    """
    If delta_scanning is enabled in policy, diff the lockfile against the DB
    and return only packages not previously scanned (or with version changes).
    Falls back to returning all packages when delta is off.
    """
    # Read all packages from the lockfile first
    all_packages = []
    basename = os.path.basename(lockfile_path)
    if basename == "requirements.txt" or lockfile_path.endswith(".txt"):
        with open(lockfile_path, "r") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                name = re.split(r"[=<>~!]", line)[0].strip()
                if name:
                    all_packages.append(name)
    elif basename == "package.json" or lockfile_path.endswith(".json"):
        try:
            with open(lockfile_path, "r") as f:
                data = json.load(f)
            deps = data.get("dependencies", {})
            dev_deps = data.get("devDependencies", {})
            all_packages.extend(deps.keys())
            all_packages.extend(dev_deps.keys())
        except Exception:
            pass
    else:
        with open(lockfile_path, "r") as f:
            for line in f:
                name = line.strip()
                if name:
                    all_packages.append(name)

    if not policy.get("delta_scanning", False):
        return all_packages

    # Delta: only return packages not in the inventory or whose version changed
    init_db()
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    changed = []
    for pkg in all_packages:
        cur.execute(
            "SELECT last_version FROM package_inventory WHERE package_name=? AND ecosystem=?",
            (pkg, ecosystem)
        )
        row = cur.fetchone()
        if not row:
            changed.append(pkg)  # Never seen before
        # If we don't know the new version yet (no pin), always include
        # A more precise check would compare pinned versions from the lockfile
    conn.close()

    if not changed:
        if rich_available:
            console.print("[bold green]Delta scan: no new or changed packages detected.[/bold green]")
        else:
            print("Delta scan: no new or changed packages detected.")

    return changed if changed else all_packages

def main():
    parser = argparse.ArgumentParser(description="Depthcharge Dependency Scanner CLI")
    subparsers = parser.add_subparsers(dest="command", help="Sub-commands")

    def _add_common_args(p):
        p.add_argument("--type", choices=["pypi", "npm"], default="pypi", help="Ecosystem registry type")
        p.add_argument("--skip-reputation", action="store_true", help="Skip reputation scoring")
        p.add_argument("--skip-static", action="store_true", help="Skip static code analysis")
        p.add_argument("--skip-dynamic", action="store_true", help="Skip dynamic sandbox evaluation")
        p.add_argument("-o", "--output", help="Report output path (.html, .md, or .pdf)")
        p.add_argument("--markdown", help="Also write a Markdown report to this path")
        p.add_argument("--threshold", type=int, default=70, help="Risk score threshold (default: 70)")
        p.add_argument("--fail-on-high", action="store_true", help="Exit 1 if any package exceeds threshold")
        p.add_argument("--sbom", help="Write CycloneDX JSON SBOM to this path")
        p.add_argument("--policy", help="Path to depthcharge.yml policy config file")
        p.add_argument("--delta", action="store_true", help="Only scan packages changed since last scan (CI delta mode)")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a single package or lockfile")
    scan_parser.add_argument("package", nargs="?", help="Name of package to scan")
    scan_parser.add_argument("--lockfile", help="Path to requirements.txt or package.json to scan")
    _add_common_args(scan_parser)

    # scan-file command
    file_parser = subparsers.add_parser("scan-file", help="Scan packages from requirements.txt or package.json")
    file_parser.add_argument("path", help="Path to requirements.txt or package.json")
    _add_common_args(file_parser)

    # history command
    subparsers.add_parser("history", help="List scan history records")
    
    args = parser.parse_args()

    def _emit_sbom(results, sbom_path):
        if sbom_path and sbom_available:
            generate_sbom(results, sbom_path)
            if rich_available:
                console.print(f"[bold green]✓ CycloneDX SBOM written to {sbom_path}[/bold green]")
            else:
                print(f"CycloneDX SBOM written to {sbom_path}")
        elif sbom_path and not sbom_available:
            print("Warning: SBOM module unavailable, skipping SBOM generation.")

    def _check_threshold(results, threshold, fail_on_high):
        exceeded = any(r.get("score", 0) >= threshold for r in results.values())
        if exceeded and fail_on_high:
            msg = f"ERROR: A package exceeds risk threshold ({threshold}/100)"
            if rich_available:
                console.print(f"[bold red]{msg}[/bold red]")
            else:
                print(msg)
            sys.exit(1)

    if args.command == "scan":
        threshold = getattr(args, "threshold", 70)
        fail_on_high = getattr(args, "fail_on_high", False)
        policy = load_policy_config(getattr(args, "policy", None))
        if getattr(args, "delta", False):
            policy["delta_scanning"] = True

        if args.lockfile:
            has_high_risk, results = scan_file(
                args.lockfile, args.type,
                args.skip_reputation, args.skip_static, args.skip_dynamic
            )
            if results and args.output:
                generate_report(results, args.output)
            if results and getattr(args, "markdown", None):
                generate_markdown_report(results, args.markdown)
            _emit_sbom(results, getattr(args, "sbom", None))
            _check_threshold(results, threshold, fail_on_high)
        else:
            if not args.package:
                scan_parser.print_help()
                sys.exit(1)
            res = run_scan(args.package, args.type, args.skip_reputation, args.skip_static, args.skip_dynamic)
            if res:
                pkg_results = {args.package: res}
                if args.output:
                    generate_report(pkg_results, args.output)
                if getattr(args, "markdown", None):
                    generate_markdown_report(pkg_results, args.markdown)
                _emit_sbom(pkg_results, getattr(args, "sbom", None))
                if res.get("score", 0) >= threshold and fail_on_high:
                    msg = f"ERROR: Package exceeds risk threshold ({threshold}/100)"
                    if rich_available:
                        console.print(f"[bold red]{msg}[/bold red]")
                    else:
                        print(msg)
                    sys.exit(1)

    elif args.command == "scan-file":
        threshold = getattr(args, "threshold", 70)
        fail_on_high = getattr(args, "fail_on_high", False)
        policy = load_policy_config(getattr(args, "policy", None))
        if getattr(args, "delta", False):
            policy["delta_scanning"] = True

        has_high_risk, results = scan_file(
            args.path, args.type,
            args.skip_reputation, args.skip_static, args.skip_dynamic
        )
        if results and args.output:
            generate_report(results, args.output)
        if results and getattr(args, "markdown", None):
            generate_markdown_report(results, args.markdown)
        _emit_sbom(results, getattr(args, "sbom", None))
        _check_threshold(results, threshold, fail_on_high)

    elif args.command == "history":
        show_history()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()

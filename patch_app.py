with open("modules/dashboard/app.py", "r") as f:
    content = f.read()

# Update run_scan_in_background signature
content = content.replace(
    'def run_scan_in_background(scan_id, package_name, ecosystem):',
    'def run_scan_in_background(scan_id, package_name, ecosystem, skip_reputation=False, skip_static=False, skip_dynamic=False):'
)

# Update run_scan_in_background logic
old_logic = """        # 1. Reputation
        rep_results = scan_reputation(package_name, ecosystem)
        if not rep_results.get("exists"):
            if rep_results.get("typosquatting_detected"):
                # Package doesn't exist but typosquatting detected — still score it
                static_results = {"typosquatting": rep_results.get("typosquatting_info"), "alerts": [], "files_scanned": 0, "obfuscation_detected": False, "dangerous_ast_detected": False, "success": False}
                dynamic_results = {"docker_available": False, "events": []}
                score_data = calculate_score(rep_results, static_results, dynamic_results)
                conn = get_db_connection()
                cursor = conn.cursor()
                cursor.execute(\"\"\"
                    UPDATE scans SET version = 'N/A', score = ?, risk_level = ?, reputation_data = ?, static_data = ?, dynamic_data = ?, reasons = ? WHERE id = ?
                \"\"\", (score_data["score"], score_data["risk_level"], json.dumps(rep_results), json.dumps(static_results), json.dumps(dynamic_results), json.dumps(score_data["reasons"]), scan_id))
                conn.commit()
                conn.close()
                return
            error_msg = rep_results.get("error", "Package not found")
            update_scan_failed(scan_id, error_msg)
            return

        # 2. Static
        download_url = rep_results.get("download_url")
        static_results = scan_static(package_name, ecosystem, download_url)

        # 3. Dynamic
        dynamic_results = scan_dynamic(package_name, ecosystem)"""

new_logic = """        # 1. Reputation
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
                cursor.execute(\"\"\"
                    UPDATE scans SET version = 'N/A', score = ?, risk_level = ?, reputation_data = ?, static_data = ?, dynamic_data = ?, reasons = ? WHERE id = ?
                \"\"\", (score_data["score"], score_data["risk_level"], json.dumps(rep_results), json.dumps(static_results), json.dumps(dynamic_results), json.dumps(score_data["reasons"]), scan_id))
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
            dynamic_results = scan_dynamic(package_name, ecosystem, download_url)"""
content = content.replace(old_logic, new_logic)

# Fix calculate_score call at the bottom
content = content.replace('score_data = calculate_score(rep_results, static_results, dynamic_results)', 'score_data = calculate_score(package_name, rep_results, static_results, dynamic_results)')

# Update trigger_scan logic
trigger_scan_old = """    data = request.json or {}
    package_name = data.get("package")
    ecosystem = data.get("ecosystem", "pypi").lower()"""

trigger_scan_new = """    data = request.json or {}
    package_name = data.get("package")
    ecosystem = data.get("ecosystem", "pypi").lower()
    skip_reputation = data.get("skip_reputation", False)
    skip_static = data.get("skip_static", False)
    skip_dynamic = data.get("skip_dynamic", False)"""
content = content.replace(trigger_scan_old, trigger_scan_new)

trigger_thread_old = """threading.Thread(target=run_scan_in_background, args=(scan_id, package_name, ecosystem)).start()"""
trigger_thread_new = """threading.Thread(target=run_scan_in_background, args=(scan_id, package_name, ecosystem, skip_reputation, skip_static, skip_dynamic)).start()"""
content = content.replace(trigger_thread_old, trigger_thread_new)

with open("modules/dashboard/app.py", "w") as f:
    f.write(content)
print("app.py patched!")

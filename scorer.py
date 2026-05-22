def calculate_score(package_name, reputation, static, dynamic):
    """
    Computes DepthCharge risk score (0 to 100) based on Marrakech PFS report guidelines.
    
    Returns per-module sub-scores (reputation, static, dynamic) and a combined total.
    
    Scoring weights:
    - Reputation module: up to 25 points (typosquatting 15 + metadata 10)
    - Static module: up to 45 points (obfuscation 25 + dangerous AST 20)
    - Dynamic module: up to 25 points (suspicious runtime)
    - Database match: +50 bonus points (known malicious)
    """
    # ── Per-module sub-scores ──
    rep_score = 0
    rep_reasons = []
    
    static_score = 0
    static_reasons = []
    
    dynamic_score = 0
    dynamic_reasons = []
    
    # ── 1. REPUTATION MODULE (max 25 base + 50 malicious bonus) ──
    # Wait, we need to increase Typosquatting penalty to 60 to make it Critical
    
    # Typosquatting detected — 70 points
    has_typosquatting = False
    if static and static.get("typosquatting"):
        has_typosquatting = True
    elif reputation and reputation.get("typosquatting_detected"):
        has_typosquatting = True
        
    if has_typosquatting:
        rep_score += 70
        rep_reasons.append("Typosquatting detected — package name is suspiciously similar to a popular package (+70 pts).")
        
    # Suspicious metadata — 10 points
    has_suspicious_metadata = False
    if reputation:
        if reputation.get("is_suspiciously_new") or reputation.get("releases_count", 0) <= 3:
            has_suspicious_metadata = True
            
    if has_suspicious_metadata:
        rep_score += 10
        rep_reasons.append("Suspicious metadata — package is brand new or has very few releases (+10 pts).")
        
    # Known malicious package match — +50 points
    is_known_malicious = False
    if reputation:
        if reputation.get("known_malicious") or reputation.get("malware_database_match"):
            is_known_malicious = True
            
    if is_known_malicious:
        rep_score += 50
        rep_reasons.append("Known malicious package match in threat database (+50 pts).")
    
    if not rep_reasons:
        rep_reasons.append("No reputation issues found.")
    
    # ── 2. STATIC MODULE (max 45) ──
    
    # Obfuscated code / high entropy — 25 points
    is_obfuscated = False
    if static and static.get("obfuscation_detected"):
        is_obfuscated = True
        
    if is_obfuscated:
        static_score += 25
        static_reasons.append("Obfuscated code or high-entropy string literals detected (+25 pts).")
        
    # Dangerous AST patterns — 20 points
    has_dangerous_ast = False
    if static and static.get("dangerous_ast_detected"):
        has_dangerous_ast = True
        
    if has_dangerous_ast:
        static_score += 20
        static_reasons.append("Dangerous AST patterns (eval/exec, base64 decoding, setup.py hooks) detected (+20 pts).")
        
    if not static_reasons:
        static_reasons.append("No static analysis threats found.")
    
    # ── 3. DYNAMIC MODULE (max 70) ──
    
    # Suspicious runtime behavior — 70 points
    has_suspicious_runtime = False
    if dynamic and dynamic.get("suspicious_runtime_detected"):
        has_suspicious_runtime = True
        
    if has_suspicious_runtime:
        dynamic_score += 70
        dynamic_reasons.append("Suspicious runtime behavior (unexpected network, process, or file activity) detected (+70 pts).")
        
    if not dynamic_reasons:
        if dynamic and dynamic.get("docker_available") == False:
            dynamic_reasons.append("Dynamic scan skipped — Docker not available.")
        else:
            dynamic_reasons.append("No suspicious runtime behavior detected.")
    
    # ── COMBINED TOTAL ──
    total_score = min(rep_score + static_score + dynamic_score, 100)
    
    # ── STRICT CASE-SENSITIVE WHITELIST FOR LEGIT PACKAGES ──
    # If the exact package name matches the whitelist, ignore non-malicious static/reputation alerts.
    # Note: If dynamic Sandbox detects unexpected outbound network (or it's known_malicious), we still flag it.
    whitelist = {"requests", "numpy", "flask", "django", "pandas", "scapy", "cryptography"}
    
    is_whitelisted = False
    if package_name in whitelist:
        # Override score for trusted legit packages to 0 (Low), UNLESS they did something dynamically malicious
        # or are explicitly marked known malicious in OSV.
        if not is_known_malicious and not has_suspicious_runtime:
            total_score = 0
            rep_score = 0
            static_score = 0
            dynamic_score = 0
            is_whitelisted = True
            rep_reasons = ["Package is explicitly whitelisted as a trusted legitimate package."]
            static_reasons = ["Ignored warnings due to package whitelist."]
            dynamic_reasons = ["Ignored warnings due to package whitelist."]
    
    # Risk Level mapping
    if total_score >= 70:
        level = "High"
    elif total_score >= 15:
        level = "Medium"
    else:
        level = "Low"
    
    # Combined reasons (legacy support)
    all_reasons = []
    if is_whitelisted:
        all_reasons.append("Package is explicitly whitelisted as a trusted legitimate package (Score overridden to 0).")
    else:
        if has_typosquatting:
            all_reasons.append("Typosquatting detected (package name is suspiciously similar to a popular package) (+70 points).")
        if has_suspicious_metadata:
            all_reasons.append("Suspicious metadata (e.g. package is brand new or has very few releases) (+10 points).")
    if is_known_malicious:
        all_reasons.append("Known malicious package match in database (+50 points).")
    if is_obfuscated:
        all_reasons.append("Obfuscated code or high-entropy string literals detected (+25 points).")
    if has_dangerous_ast:
        all_reasons.append("Dangerous AST patterns (e.g. eval/exec, base64 decoding chains, setup.py install/network hooks) detected (+20 points).")
    if has_suspicious_runtime:
        all_reasons.append("Suspicious runtime behavior (e.g. unexpected socket connect, child process spawn, file writes outside install directory) detected (+70 points).")
    if not all_reasons:
        all_reasons = ["No suspicious indicators found. Package appears safe."]
        
    return {
        "score": total_score,
        "risk_level": level,
        "reasons": all_reasons,
        "module_scores": {
            "reputation": {
                "score": min(rep_score, 100),
                "max": 75,
                "reasons": rep_reasons
            },
            "static": {
                "score": min(static_score, 100),
                "max": 45,
                "reasons": static_reasons
            },
            "dynamic": {
                "score": min(dynamic_score, 100),
                "max": 70,
                "reasons": dynamic_reasons
            }
        },
        "breakdown": {
            "obfuscation": 25 if is_obfuscated else 0,
            "dangerous_ast": 20 if has_dangerous_ast else 0,
            "suspicious_runtime": 70 if has_suspicious_runtime else 0,
            "typosquatting": 70 if has_typosquatting else 0,
            "suspicious_metadata": 10 if has_suspicious_metadata else 0,
            "known_malicious": 50 if is_known_malicious else 0
        }
    }

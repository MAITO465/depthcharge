"""
Depthcharge risk scorer.

Scoring model:
  Reputation   up to 25 pts  (typosquatting 70, metadata 10, known malicious +50)
  Static       up to 45 pts  (obfuscation 25, dangerous AST 20)
  Dynamic      up to 25 pts  (suspicious runtime 70)

  Combination bonuses:
    setup_hook_danger  AND  dynamic process/network  →  +15 bonus (corroborated)
    obfuscation        AND  dangerous_ast            →  +10 bonus (stacked signal)
    taint_flow         (any)                         →  +10 bonus (data-flow confirmed)
    ioc_match          (any)                         →  +15 bonus (direct C2 hit)

  False-positive suppression:
    Known-legit packages on the strict whitelist are zeroed out unless
    dynamic sandbox catches something or OSV flags it as malicious.
"""

from __future__ import annotations
from typing import Any


# ── Strict legit whitelist ────────────────────────────────────────────────────
_STRICT_WHITELIST = {
    "requests", "numpy", "flask", "django", "pandas", "scapy",
    "cryptography", "awscli", "awscli-login", "boto3",
}


def _count_finding_type(alerts: list[dict], ftype: str) -> int:
    return sum(1 for a in alerts if a.get("type") == ftype)


def _has_setup_hook_finding(alerts: list[dict]) -> bool:
    return any(
        a.get("type") == "setup_hook_danger" and a.get("confidence") in ("high", None)
        for a in alerts
    )


def calculate_score(
    package_name: str,
    reputation: dict[str, Any],
    static: dict[str, Any],
    dynamic: dict[str, Any],
) -> dict[str, Any]:
    """
    Returns:
        score         int 0–100
        risk_level    "High" | "Medium" | "Low"
        reasons       list[str]
        breakdown     dict of contributing component scores
        module_scores dict (for dashboard/PDF)
    """
    alerts: list[dict] = static.get("alerts", []) if static else []

    rep_score = 0
    rep_reasons: list[str] = []

    static_score = 0
    static_reasons: list[str] = []

    dynamic_score = 0
    dynamic_reasons: list[str] = []

    combination_bonus = 0
    combination_reasons: list[str] = []

    # ── 1. REPUTATION ─────────────────────────────────────────────────────────
    has_typosquatting = bool(
        (static and static.get("typosquatting")) or
        (reputation and reputation.get("typosquatting_detected"))
    )
    if has_typosquatting:
        rep_score += 70
        rep_reasons.append("Typosquatting detected — package name is suspiciously similar to a popular package (+70 pts).")

    has_suspicious_metadata = bool(
        reputation and (
            reputation.get("is_suspiciously_new") or
            reputation.get("releases_count", 999) <= 3
        )
    )
    if has_suspicious_metadata:
        rep_score += 10
        rep_reasons.append("Suspicious metadata — brand new or very few releases (+10 pts).")

    is_known_malicious = bool(
        reputation and (
            reputation.get("known_malicious") or reputation.get("malware_database_match")
        )
    )
    if is_known_malicious:
        rep_score += 50
        rep_reasons.append("Known malicious package match in threat database (+50 pts).")

    # Maintainer change flag (set by reputation checker)
    has_maintainer_change = bool(reputation and reputation.get("maintainer_changed"))
    if has_maintainer_change:
        rep_score += 30
        rep_reasons.append("Maintainer email changed since last known scan — possible account takeover (+30 pts).")

    if not rep_reasons:
        rep_reasons.append("No reputation issues found.")

    # ── 2. STATIC ─────────────────────────────────────────────────────────────
    is_obfuscated = bool(static and static.get("obfuscation_detected"))
    if is_obfuscated:
        static_score += 25
        static_reasons.append("Obfuscated code or high-entropy string literals detected (+25 pts).")

    has_dangerous_ast = bool(static and static.get("dangerous_ast_detected"))
    if has_dangerous_ast:
        static_score += 20
        static_reasons.append("Dangerous AST patterns (eval/exec, base64 chains, install hooks) detected (+20 pts).")

    # IoC direct hit
    has_ioc = bool(static and static.get("ioc_matches"))
    if has_ioc:
        ioc_count = len(static.get("ioc_matches", []))
        static_score += 15
        static_reasons.append(f"Direct IoC match ({ioc_count} finding(s) — C2 domain / bot token / exfil URL) (+15 pts).")

    # Taint flow bonus (already contributes via dangerous_ast, give extra signal)
    has_taint = bool(static and static.get("taint_flows_detected"))

    if not static_reasons:
        static_reasons.append("No static analysis threats found.")

    # ── 3. DYNAMIC ────────────────────────────────────────────────────────────
    has_suspicious_runtime = bool(dynamic and dynamic.get("suspicious_runtime_detected"))
    if has_suspicious_runtime:
        dynamic_score += 70
        dynamic_reasons.append("Suspicious runtime behaviour (unexpected network/process/file) detected (+70 pts).")

    if not dynamic_reasons:
        if dynamic and dynamic.get("docker_available") is False:
            dynamic_reasons.append("Dynamic scan skipped — Docker not available.")
        else:
            dynamic_reasons.append("No suspicious runtime behaviour detected.")

    # ── 4. COMBINATION SCORING ────────────────────────────────────────────────
    # setup.py hook AND runtime process spawn → corroborated, higher confidence
    if _has_setup_hook_finding(alerts) and has_suspicious_runtime:
        combination_bonus += 15
        combination_reasons.append(
            "Combination: setup hook danger corroborated by dynamic sandbox process spawn (+15 pts)."
        )

    # Obfuscation AND dangerous AST together → stacked signal
    if is_obfuscated and has_dangerous_ast:
        combination_bonus += 10
        combination_reasons.append(
            "Combination: obfuscation AND dangerous AST patterns both present — stacked signal (+10 pts)."
        )

    # Confirmed taint flow
    if has_taint:
        combination_bonus += 10
        combination_reasons.append(
            "Taint flow: external data confirmed flowing into a dangerous sink (+10 pts)."
        )

    # Direct IoC hit combined with network activity
    if has_ioc and has_suspicious_runtime:
        combination_bonus += 15
        combination_reasons.append(
            "Combination: IoC match corroborated by runtime network activity — active C2 contact likely (+15 pts)."
        )

    # ── TOTAL ─────────────────────────────────────────────────────────────────
    total_score = min(rep_score + static_score + dynamic_score + combination_bonus, 100)

    # ── WHITELIST OVERRIDE ────────────────────────────────────────────────────
    is_whitelisted = False
    if package_name in _STRICT_WHITELIST:
        if not is_known_malicious and not has_suspicious_runtime:
            total_score = 0
            rep_score = static_score = dynamic_score = combination_bonus = 0
            is_whitelisted = True
            rep_reasons = ["Package is on the trusted whitelist — score overridden to 0."]
            static_reasons = ["Suppressed — package is on trusted whitelist."]
            dynamic_reasons = ["Suppressed — package is on trusted whitelist."]
            combination_reasons = []

    # ── RISK LEVEL ────────────────────────────────────────────────────────────
    if total_score >= 70:
        level = "High"
    elif total_score >= 15:
        level = "Medium"
    else:
        level = "Low"

    # ── REMEDIATION HINT ─────────────────────────────────────────────────────
    remediation: str | None = None
    if total_score >= 70:
        prev_clean = reputation.get("prev_version") if reputation else None
        if has_ioc:
            remediation = (
                f"BLOCKED — Direct IoC (C2/token/exfil URL) detected. "
                f"{'Last known clean version: ' + prev_clean + '.' if prev_clean else 'No prior clean version on record.'} "
                "Do not install. Investigate maintainer account for compromise."
            )
        elif _has_setup_hook_finding(alerts):
            trigger_finding = next(
                (a for a in alerts if a.get("type") == "setup_hook_danger"), None
            )
            loc = ""
            if trigger_finding:
                loc = f" ({trigger_finding['file']}:{trigger_finding['line']})"
            remediation = (
                f"BLOCKED — Dangerous install hook{loc}. "
                f"{'Last clean version: ' + prev_clean + '.' if prev_clean else ''} "
                "Pin to a verified clean version or find an alternative package."
            )
        elif has_typosquatting:
            typo_info = (static or {}).get("typosquatting") or (reputation or {}).get("typosquatting_info", {})
            target = typo_info.get("target", "a popular package") if typo_info else "a popular package"
            remediation = (
                f"BLOCKED — Possible typosquatting of '{target}'. "
                "Verify the intended package name and install the correct one."
            )
        else:
            remediation = (
                f"BLOCKED — Multiple high-severity findings. "
                f"{'Last clean version: ' + prev_clean + '.' if prev_clean else ''} "
                "Conduct manual review before allowing this package."
            )

    # ── COMBINED REASONS (for legacy/display) ────────────────────────────────
    all_reasons: list[str] = []
    if is_whitelisted:
        all_reasons.append("Package is on the trusted whitelist (score overridden to 0).")
    else:
        if has_typosquatting:
            all_reasons.append("Typosquatting detected (+70 pts).")
        if has_suspicious_metadata:
            all_reasons.append("Suspicious metadata — brand new or very few releases (+10 pts).")
        if has_maintainer_change:
            all_reasons.append("Maintainer email changed since last scan — possible account takeover (+30 pts).")
    if is_known_malicious:
        all_reasons.append("Known malicious package in threat database (+50 pts).")
    if is_obfuscated:
        all_reasons.append("Obfuscated code or high-entropy string literals detected (+25 pts).")
    if has_dangerous_ast:
        all_reasons.append("Dangerous AST patterns detected (+20 pts).")
    if has_ioc:
        all_reasons.append(f"Direct IoC match — C2 domain / bot token / exfil URL detected (+15 pts).")
    if has_suspicious_runtime:
        all_reasons.append("Suspicious runtime behaviour detected (+70 pts).")
    all_reasons.extend(combination_reasons)
    if not all_reasons:
        all_reasons = ["No suspicious indicators found. Package appears safe."]

    if remediation:
        all_reasons.append(f"Remediation: {remediation}")

    return {
        "score": total_score,
        "risk_level": level,
        "reasons": all_reasons,
        "remediation": remediation,
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
            },
            "combination": {
                "score": combination_bonus,
                "max": 50,
                "reasons": combination_reasons
            },
        },
        "breakdown": {
            "obfuscation":        25 if is_obfuscated else 0,
            "dangerous_ast":      20 if has_dangerous_ast else 0,
            "ioc_match":          15 if has_ioc else 0,
            "suspicious_runtime": 70 if has_suspicious_runtime else 0,
            "typosquatting":      70 if has_typosquatting else 0,
            "suspicious_metadata": 10 if has_suspicious_metadata else 0,
            "known_malicious":    50 if is_known_malicious else 0,
            "maintainer_change":  30 if has_maintainer_change else 0,
            "combination_bonus":  combination_bonus,
        },
    }

"""
CycloneDX SBOM generator (spec 1.4 JSON subset).

Usage:
    from modules.sbom.generator import generate_sbom
    sbom = generate_sbom(results_dict, output_path="sbom.json")
"""

from __future__ import annotations
import json
import uuid
from datetime import datetime, timezone
from typing import Any


def _purl(ecosystem: str, name: str, version: str) -> str:
    eco = ecosystem.lower()
    if eco == "pypi":
        return f"pkg:pypi/{name.lower()}@{version}"
    elif eco == "npm":
        return f"pkg:npm/{name}@{version}"
    return f"pkg:{eco}/{name}@{version}"


def _risk_rating(risk_level: str) -> str:
    mapping = {"High": "critical", "Medium": "medium", "Low": "low"}
    return mapping.get(risk_level, "unknown")


def generate_sbom(
    results: dict[str, Any],
    output_path: str | None = None,
    tool_version: str = "1.0.0",
) -> dict:
    """
    Build a CycloneDX 1.4 JSON SBOM from Depthcharge scan results.

    results: { package_name: scan_result_dict }
    Returns the SBOM dict (also writes to output_path if given).
    """
    now = datetime.now(timezone.utc).isoformat()

    components = []
    for pkg_name, result in results.items():
        rep = result.get("reputation") or {}
        static = result.get("static") or {}
        ecosystem = rep.get("ecosystem", "pypi")
        version = rep.get("version", "unknown") or "unknown"
        score = result.get("score", 0)
        risk_level = result.get("risk_level", "Low")
        vulns = rep.get("vulnerabilities") or []

        # Build properties list from findings
        properties = [
            {"name": "depthcharge:risk_score", "value": str(score)},
            {"name": "depthcharge:risk_level", "value": risk_level},
            {"name": "depthcharge:files_scanned", "value": str(static.get("files_scanned", 0))},
            {"name": "depthcharge:obfuscation_detected", "value": str(static.get("obfuscation_detected", False))},
            {"name": "depthcharge:dangerous_ast_detected", "value": str(static.get("dangerous_ast_detected", False))},
            {"name": "depthcharge:taint_flows_detected", "value": str(static.get("taint_flows_detected", False))},
            {"name": "depthcharge:ioc_matches", "value": str(len(static.get("ioc_matches", [])))},
        ]

        # ATT&CK techniques present in this component
        mitre_ids = sorted({
            a.get("mitre_id")
            for a in static.get("alerts", [])
            if a.get("mitre_id") and a["mitre_id"] != "T0000"
        })
        for mid in mitre_ids:
            properties.append({"name": "depthcharge:mitre_technique", "value": mid})

        # CycloneDX vulnerabilities array (from OSV data)
        cdx_vulns = []
        for v in vulns:
            cdx_vulns.append({
                "id": v.get("id", "UNKNOWN"),
                "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{v.get('id', '')}"},
                "description": v.get("summary", ""),
                "ratings": [{"severity": "high"}],
            })

        component = {
            "type": "library",
            "bom-ref": f"{pkg_name}@{version}",
            "name": pkg_name,
            "version": version,
            "purl": _purl(ecosystem, pkg_name, version),
            "description": rep.get("summary", ""),
            "externalReferences": [
                {"type": "website", "url": rep.get("home_page", "")}
            ] if rep.get("home_page") else [],
            "properties": properties,
            "vulnerabilities": cdx_vulns,
        }
        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": now,
            "tools": [
                {
                    "vendor": "Depthcharge",
                    "name": "depthcharge",
                    "version": tool_version,
                }
            ],
            "component": {
                "type": "application",
                "name": "scanned-project",
                "version": "unknown",
            },
        },
        "components": components,
    }

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2)

    return sbom

import os
import requests
import json
import tarfile
import tempfile
import shutil
import re
from datetime import datetime
from packaging.version import parse as parse_version
import Levenshtein

OSV_URL = "https://api.osv.dev/v1/query"

# Local cache directory for popular package lists
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "depthcharge")
os.makedirs(CACHE_DIR, exist_ok=True)

PYPI_TOP_5000_URL = "https://hugovk.dev/top-pypi-packages/top-pypi-packages.min.json"
NPM_TOP_JS_URL = "https://raw.githubusercontent.com/wooorm/npm-high-impact/main/lib/top.js"

# Basic fallback popular packages lists
PYPI_FALLBACK = [
    "requests", "urllib3", "numpy", "pandas", "cryptography", "jinja2", "click", "boto3",
    "django", "flask", "pydantic", "pyyaml", "certifi", "six", "wheel", "setuptools",
    "pytest", "black", "isort", "pip", "virtualenv", "poetry", "ansible", "matplotlib"
]

NPM_FALLBACK = [
    "lodash", "react", "vue", "express", "chalk", "request", "async", "commander",
    "uuid", "axios", "debug", "moment", "fs-extra", "dotenv", "glob", "minimist",
    "tslib", "semver", "mkdirp", "bluebird", "webpack", "babel-core", "inquirer"
]

def load_popular_packages(ecosystem):
    ecosystem = ecosystem.lower()
    cache_file = os.path.join(CACHE_DIR, f"{ecosystem}_top_5000.json")
    
    # Try loading from cache first
    if os.path.exists(cache_file):
        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
                if data and len(data) > 100:
                    return data
        except Exception:
            pass

    # Try downloading Top PyPI packages
    if ecosystem == "pypi":
        try:
            r = requests.get(PYPI_TOP_5000_URL, timeout=10)
            if r.status_code == 200:
                rows = r.json().get("rows", [])
                names = [row["project"] for row in rows if "project" in row]
                if len(names) > 100:
                    with open(cache_file, "w") as f:
                        json.dump(names, f)
                    return names
        except Exception:
            pass
        return PYPI_FALLBACK

    # Try downloading Top NPM packages
    elif ecosystem == "npm":
        try:
            r = requests.get(NPM_TOP_JS_URL, timeout=10)
            if r.status_code == 200:
                # Basic parsing of the wooorm top.js file structure:
                # export const top = [ 'semver', ... ]
                text = r.text
                names = []
                for match in re.finditer(r"'(.*?)'", text):
                    names.append(match.group(1))
                if len(names) > 100:
                    with open(cache_file, "w") as f:
                        json.dump(names, f)
                    return names
        except Exception:
            pass
        return NPM_FALLBACK

    return []

def check_typosquatting(package_name, ecosystem):
    targets = load_popular_packages(ecosystem)
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
                "message": f"Package '{original_name}' uses unusual casing of popular package '{canonical}'. Possible typosquatting via case confusion."
            }
        return None
        
    for target in targets:
        dist = Levenshtein.distance(package_lower, target.lower())
        if 0 < dist <= 2:
            return {
                "target": target,
                "distance": dist,
                "message": f"Package '{original_name}' is suspiciously close to popular package '{target}' (edit distance: {dist}). Possible typosquatting."
            }
    return None

def check_osv_vulnerabilities(package_name, ecosystem, version=None):
    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI" if ecosystem.lower() == "pypi" else "npm"
        }
    }
    if version and version != "Unknown":
        payload["version"] = version
    try:
        response = requests.post(OSV_URL, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulns", [])
            results = []
            for v in vulns:
                results.append({
                    "id": v.get("id"),
                    "summary": v.get("summary", "No summary provided"),
                    "details": v.get("details", ""),
                    "aliases": v.get("aliases", []),
                    "modified": v.get("modified", "")
                })
            return results
    except Exception as e:
        print(f"[Reputation] Error querying OSV for {package_name}: {e}")
    return []

def get_pypi_metadata(package_name):
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            info = data.get("info", {})
            releases = data.get("releases", {})
            
            release_dates = []
            for ver, files in releases.items():
                for f in files:
                    if "upload_time" in f:
                        try:
                            release_dates.append(datetime.strptime(f["upload_time"], "%Y-%m-%dT%H:%M:%S"))
                        except ValueError:
                            pass
            
            created_at = min(release_dates).isoformat() if release_dates else "Unknown"
            latest_release_at = max(release_dates).isoformat() if release_dates else "Unknown"
            
            download_url = ""
            for u in data.get("urls", []):
                if u.get("packagetype") == "sdist":
                    download_url = u.get("url")
                    break
            if not download_url and data.get("urls"):
                download_url = data["urls"][0].get("url")
            
            # Find previous version
            sorted_versions = sorted(releases.keys(), key=parse_version)
            prev_version = None
            curr_version = info.get("version")
            if curr_version in sorted_versions:
                idx = sorted_versions.index(curr_version)
                if idx > 0:
                    prev_version = sorted_versions[idx - 1]
            
            return {
                "exists": True,
                "name": info.get("name", package_name),
                "author": info.get("author", "Unknown"),
                "author_email": info.get("author_email", "Unknown"),
                "version": curr_version,
                "prev_version": prev_version,
                "summary": info.get("summary", ""),
                "home_page": info.get("home_page") or info.get("project_url", ""),
                "license": info.get("license", "Unknown"),
                "releases_count": len(releases),
                "created_at": created_at,
                "latest_release_at": latest_release_at,
                "download_url": download_url or info.get("download_url") or "",
                "all_releases": releases
            }
        elif response.status_code == 404:
            return {"exists": False, "error": "Package not found on PyPI"}
    except Exception as e:
        return {"exists": False, "error": str(e)}
    return {"exists": False, "error": "Failed to retrieve package metadata from PyPI"}

def get_npm_metadata(package_name):
    safe_name = package_name.replace("/", "%2F")
    url = f"https://registry.npmjs.org/{safe_name}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            dist_tags = data.get("dist-tags", {})
            latest_version = dist_tags.get("latest", "Unknown")
            
            latest_data = data.get("versions", {}).get(latest_version, {})
            time_data = data.get("time", {})
            
            created_at = time_data.get("created", "Unknown")
            latest_release_at = time_data.get(latest_version, "Unknown")
            
            author_data = latest_data.get("author", {})
            if isinstance(author_data, dict):
                author = author_data.get("name", "Unknown")
                author_email = author_data.get("email", "Unknown")
            else:
                author = str(author_data)
                author_email = "Unknown"
                
            # Find previous version
            all_versions = list(data.get("versions", {}).keys())
            sorted_versions = sorted(all_versions, key=parse_version)
            prev_version = None
            if latest_version in sorted_versions:
                idx = sorted_versions.index(latest_version)
                if idx > 0:
                    prev_version = sorted_versions[idx - 1]

            return {
                "exists": True,
                "name": data.get("name", package_name),
                "author": author,
                "author_email": author_email,
                "version": latest_version,
                "prev_version": prev_version,
                "summary": data.get("description", ""),
                "home_page": data.get("homepage", ""),
                "license": latest_data.get("license", "Unknown"),
                "releases_count": len(data.get("versions", {})),
                "created_at": created_at,
                "latest_release_at": latest_release_at,
                "download_url": latest_data.get("dist", {}).get("tarball", ""),
                "all_versions_data": data.get("versions", {})
            }
        elif response.status_code == 404:
            return {"exists": False, "error": "Package not found on NPM"}
    except Exception as e:
        return {"exists": False, "error": str(e)}
    return {"exists": False, "error": "Failed to retrieve package metadata from NPM"}

def get_npm_version_download_url(metadata, version):
    if not version:
        return ""
    ver_data = metadata.get("all_versions_data", {}).get(version, {})
    return ver_data.get("dist", {}).get("tarball", "")

def get_pypi_version_download_url(metadata, version):
    if not version:
        return ""
    urls = metadata.get("all_releases", {}).get(version, [])
    download_url = ""
    for u in urls:
        if u.get("packagetype") == "sdist":
            download_url = u.get("url")
            break
    if not download_url and urls:
        download_url = urls[0].get("url")
    return download_url

def perform_version_diff(package_name, ecosystem, metadata):
    """
    Downloads current version and previous version, and checks for unexpected additions
    to files, install hooks or setup scripts.
    """
    diff_results = {
        "files_added": [],
        "hooks_changed": False,
        "suspicious_diff": False,
        "message": ""
    }
    
    prev_version = metadata.get("prev_version")
    curr_version = metadata.get("version")
    if not prev_version or not curr_version:
        return diff_results
        
    # Get download URLs
    if ecosystem.lower() == "pypi":
        curr_url = metadata.get("download_url")
        prev_url = get_pypi_version_download_url(metadata, prev_version)
    else:
        curr_url = metadata.get("download_url")
        prev_url = get_npm_version_download_url(metadata, prev_version)
        
    if not curr_url or not prev_url:
        return diff_results
        
    temp_dir = tempfile.mkdtemp(prefix="depthcharge_diff_")
    try:
        # Download and extract current version
        curr_archive = os.path.join(temp_dir, "curr.tar.gz")
        curr_extract = os.path.join(temp_dir, "curr_extracted")
        r1 = requests.get(curr_url, timeout=15)
        with open(curr_archive, "wb") as f:
            f.write(r1.content)
        with tarfile.open(curr_archive, "r:gz") as tar:
            tar.extractall(path=curr_extract)
            
        # Download and extract previous version
        prev_archive = os.path.join(temp_dir, "prev.tar.gz")
        prev_extract = os.path.join(temp_dir, "prev_extracted")
        r2 = requests.get(prev_url, timeout=15)
        with open(prev_archive, "wb") as f:
            f.write(r2.content)
        with tarfile.open(prev_archive, "r:gz") as tar:
            tar.extractall(path=prev_extract)
            
        # Compare lists of files (basenames)
        curr_files = []
        for root, dirs, files in os.walk(curr_extract):
            for file in files:
                curr_files.append(os.path.relpath(os.path.join(root, file), curr_extract))
                
        prev_files = []
        for root, dirs, files in os.walk(prev_extract):
            for file in files:
                prev_files.append(os.path.relpath(os.path.join(root, file), prev_extract))
                
        added = set(curr_files) - set(prev_files)
        diff_results["files_added"] = list(added)
        
        # Check if setup.py or package.json hooks are changed
        # Simple detection: check if new executable scripts are added
        if any(f.endswith(".sh") or f.endswith(".bat") or "setup.py" in f or "package.json" in f for f in added):
            diff_results["hooks_changed"] = True
            diff_results["suspicious_diff"] = True
            diff_results["message"] = f"Detected new script/setup/JSON files in version {curr_version} compared to {prev_version}."
            
    except Exception as e:
        print(f"[Reputation] Error diffing versions: {e}")
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
        
    return diff_results

def scan_reputation(package_name, ecosystem="pypi"):
    ecosystem = ecosystem.lower()
    if ecosystem == "pypi":
        meta = get_pypi_metadata(package_name)
    elif ecosystem == "npm":
        meta = get_npm_metadata(package_name)
    else:
        return {"exists": False, "error": f"Unsupported ecosystem: {ecosystem}"}
        
    if not meta.get("exists"):
        # Still check typosquatting even if the package doesn't exist on the registry
        # (e.g., it could be a taken-down malicious package or a dependency confusion attempt)
        typo = check_typosquatting(package_name, ecosystem)
        if typo:
            meta["typosquatting_detected"] = True
            meta["typosquatting_info"] = typo
        else:
            meta["typosquatting_detected"] = False
        return meta
        
    # Levenshtein distance check for typosquatting
    typo = check_typosquatting(package_name, ecosystem)
    if typo:
        meta["typosquatting_detected"] = True
        meta["typosquatting_info"] = typo
    else:
        meta["typosquatting_detected"] = False
        
    # Query OSV database for known vulnerabilities
    version = meta.get("version")
    vulns = check_osv_vulnerabilities(package_name, ecosystem, version)
    meta["vulnerabilities"] = vulns
    
    # Metadata analysis: Check age and release history
    is_new = False
    if meta["created_at"] != "Unknown":
        try:
            created_str = meta["created_at"]
            if "T" in created_str:
                created_str = created_str.split("T")[0]
            created_date = datetime.strptime(created_str, "%Y-%m-%d")
            days_old = (datetime.utcnow() - created_date).days
            meta["days_old"] = days_old
            if days_old < 30:
                is_new = True
        except Exception:
            meta["days_old"] = "Unknown"
    else:
        meta["days_old"] = "Unknown"
        
    meta["is_suspiciously_new"] = is_new
    
    # Version diff check
    diff = perform_version_diff(package_name, ecosystem, meta)
    meta["version_diff"] = diff
    
    # Known malware database indicator
    # E.g. matches OSV critical malware reports or is explicitly flagged
    meta["known_malicious"] = False
    for v in vulns:
        details = v.get("details", "").lower()
        summary = v.get("summary", "").lower()
        if "malicious" in details or "malware" in details or "malicious" in summary or "malware" in summary:
            meta["known_malicious"] = True
            
    return meta

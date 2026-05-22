import os
import subprocess
import json
import shutil
import tempfile
import requests
from urllib.parse import urlparse

def _get_docker_env():
    env = os.environ.copy()
    mac_docker_bin = "/Applications/Docker.app/Contents/Resources/bin"
    if os.path.exists(mac_docker_bin):
        path = env.get("PATH", "")
        if mac_docker_bin not in path.split(os.pathsep):
            env["PATH"] = f"{mac_docker_bin}{os.pathsep}{path}" if path else mac_docker_bin
    return env

def _get_docker_binary():
    env = _get_docker_env()
    try:
        res = subprocess.run(["docker", "info"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        if res.returncode == 0:
            return "docker"
    except Exception:
        pass

    mac_docker = "/Applications/Docker.app/Contents/Resources/bin/docker"
    if os.path.exists(mac_docker):
        try:
            res = subprocess.run([mac_docker, "info"], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            if res.returncode == 0:
                return mac_docker
        except Exception:
            pass

    return None

def is_docker_available():
    return _get_docker_binary() is not None

def _image_exists(image_name="depthcharge-sandbox"):
    """Check if a Docker image already exists locally."""
    docker_bin = _get_docker_binary()
    if not docker_bin:
        return False
    try:
        res = subprocess.run(
            [docker_bin, "image", "inspect", image_name],
            env=_get_docker_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        return res.returncode == 0
    except Exception:
        return False

def build_sandbox_image():
    docker_bin = _get_docker_binary()
    if not docker_bin:
        return False, "Docker is not available or not running."
        
    sandbox_dir = os.path.dirname(os.path.abspath(__file__))
    try:
        print(f"[Sandbox] Building Docker image 'depthcharge-sandbox' from {sandbox_dir}...")
        res = subprocess.run(
            [docker_bin, "build", "-t", "depthcharge-sandbox", sandbox_dir],
            env=_get_docker_env(),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        if res.returncode != 0:
            return False, f"Docker build failed:\n{res.stderr}"
        return True, "Docker image built successfully."
    except Exception as e:
        return False, f"Failed to run docker build: {e}"

def scan_dynamic(package_name, ecosystem, download_url=None):
    """
    Runs the dependency installation and import inside a network-isolated Docker sandbox.
    Monitors all process spawning, network connection attempts, and unauthorized file writes using strace.
    """
    results = {
        "success": False,
        "docker_available": False,
        "installation_success": False,
        "installation_log": "",
        "import_success": False,
        "import_error": None,
        "events": [],
        "suspicious_runtime_detected": False,
        "error": None
    }
    
    docker_bin = _get_docker_binary()
    if not docker_bin:
        results["error"] = "Docker is not available. Please start Docker Desktop to enable dynamic scans."
        return results
        
    results["docker_available"] = True
    
    # 1. Ensure image is built and contains strace
    if not _image_exists():
        img_built, msg = build_sandbox_image()
        if not img_built:
            results["error"] = msg
            return results

    package_name = package_name.strip()
    eco = ecosystem.lower()
    
    # 2. Get download URL if not provided
    if not download_url:
        try:
            if eco == "pypi":
                meta_url = f"https://pypi.org/pypi/{package_name}/json"
                r = requests.get(meta_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    for u in data.get("urls", []):
                        if u.get("packagetype") == "sdist":
                            download_url = u.get("url")
                            break
                    if not download_url and data.get("urls"):
                        download_url = data["urls"][0].get("url")
            elif eco == "npm":
                safe_name = package_name.replace("/", "%2F")
                meta_url = f"https://registry.npmjs.org/{safe_name}"
                r = requests.get(meta_url, timeout=10)
                if r.status_code == 200:
                    data = r.json()
                    latest = data.get("dist-tags", {}).get("latest")
                    if latest:
                        download_url = data.get("versions", {}).get(latest, {}).get("dist", {}).get("tarball")
        except Exception as e:
            results["error"] = f"Failed to retrieve download URL for sandboxed execution: {e}"
            return results

    if not download_url:
        results["error"] = f"No archive download URL found for package {package_name}"
        return results

    # 3. Download package archive to a host temp directory
    temp_host_dir = tempfile.mkdtemp(prefix="depthcharge_sandbox_host_")
    parsed_url = urlparse(download_url)
    archive_name = os.path.basename(parsed_url.path)
    if not archive_name:
        archive_name = "package.tar.gz"
        
    archive_path = os.path.join(temp_host_dir, archive_name)
    
    try:
        if download_url.startswith("file://"):
            local_path = download_url[7:]
            shutil.copy(local_path, archive_path)
        else:
            r = requests.get(download_url, timeout=30, stream=True)
            if r.status_code != 200:
                results["error"] = f"Failed to download archive for sandbox: HTTP {r.status_code}"
                return results
            with open(archive_path, "wb") as f:
                for chunk in r.iter_content(chunk_size=8192):
                    f.write(chunk)
    except Exception as e:
        results["error"] = f"Failed to download archive for sandbox: {e}"
        shutil.rmtree(temp_host_dir, ignore_errors=True)
        return results

    # 4. Prepare Docker run command
    # Mount host archive temp directory, block network, grant SYS_PTRACE capability
    cmd = [
        docker_bin, "run", "--rm",
        "--network", "none",
        "--cap-add", "SYS_PTRACE",
        "--memory", "512m",
        "--pids-limit", "256",
        "-v", f"{temp_host_dir}:/package:ro",
        "depthcharge-sandbox",
        "python", "/app/sandbox_monitor.py", eco, package_name, archive_name
    ]

    try:
        print(f"[Sandbox] Executing dynamic analysis for {eco} package '{package_name}' inside network-isolated Docker...")
        res = subprocess.run(cmd, env=_get_docker_env(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=180)
        
        stdout = res.stdout
        stderr = res.stderr
        results["installation_log"] = f"STDOUT:\n{stdout}\nSTDERR:\n{stderr}"
        
        # Parse the JSON results from stdout
        marker = "===DCHARGE_RESULTS==="
        if marker in stdout:
            parts = stdout.rsplit(marker, 1)
            results_json_str = parts[-1].strip()
            try:
                run_data = json.loads(results_json_str)
                results["installation_success"] = True
                results["import_success"] = run_data.get("status") == "success"
                results["import_error"] = run_data.get("error")
                results["events"] = run_data.get("events", [])
                
                # Flag suspicious runtime if any connection, spawn, or sensitive file write is found
                if results["events"]:
                    results["suspicious_runtime_detected"] = True
                    
                results["success"] = True
            except Exception as e:
                results["error"] = f"Failed to parse monitor script output: {e}. Output was: {stdout}"
        else:
            results["installation_success"] = False
            results["error"] = f"Package installation or import execution failed inside container. Exit code: {res.returncode}. Stderr: {stderr}"
            
    except subprocess.TimeoutExpired:
        results["error"] = "Dynamic scan timed out (limit: 180s)."
    except Exception as e:
        results["error"] = f"Execution error during dynamic scan: {e}"
    finally:
        shutil.rmtree(temp_host_dir, ignore_errors=True)
        
    return results

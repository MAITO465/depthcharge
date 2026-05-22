import sys
import os
import subprocess
import json
import re

def is_event_suspicious(ev):
    ev_type = ev.get("type")
    details = ev.get("details", "")
    
    if ev_type == "network_connection":
        # Extract port and host/IP
        port_match = re.search(r':(\d+)', details)
        ip_match = re.search(r'(?:to|connect to)\s+([^\s:]+)', details)
        
        port = port_match.group(1) if port_match else ""
        ip = ip_match.group(1) if ip_match else ""
        
        # Strip trailing/leading characters from IP
        ip = ip.strip("`'\"()[],")
        
        if port == "53":
            return False
        if ip in ["127.0.0.1", "127.0.0.11", "localhost", "::1"]:
            return False
        if ip.startswith("192.168.") and port == "53":
            return False
            
    elif ev_type == "process_spawn":
        # Extract binary name
        bin_match = re.search(r'(?:spawn process|exec command|system command):\s*([^\s]+)', details)
        if bin_match:
            executable = os.path.basename(bin_match.group(1)).strip("`'\"(),[]")
            executable = re.sub(r'[^a-zA-Z0-9_\-\.]', '', executable).lower()
            
            whitelisted_binaries = [
                "pip", "npm", "node", "python", "gcc", "g++", "clang", "make", "ld", "as", 
                "uname", "lsb_release", "git", "pkg-config", "sh", "bash", "tar", "gzip", 
                "bzip2", "unzip", "distutils", "egg_info", "setup.py"
            ]
            
            if executable in whitelisted_binaries or re.match(r'^python\d', executable):
                return False
                
    return True

def parse_strace_log(log_path):
    events = []
    if not os.path.exists(log_path):
        return events

    # Regex for connect syscall (AF_INET/AF_INET6)
    connect_regex = re.compile(
        r'connect\(\d+,\s*\{sa_family=(AF_INET6?),\s*sin6?_port=htons\((\d+)\)(?:,\s*sin6_flowinfo=\d+)?(?:,\s*(?:sin_addr=inet_addr\("([^"]+)"\)|inet_pton\(AF_INET6,\s*"([^"]+)"\)))?'
    )
    
    # Regex for execve
    execve_regex = re.compile(r'execve\("([^"]+)",\s*\[([^\]]+)\]')

    # Regex for open/openat/creat
    open_regex = re.compile(r'(?:open|openat|creat)\((?:[^,]+,\s*)?"([^"]+)"')

    allowed_write_prefixes = [
        "/tmp/",
        "/app/",
        "/package/",
        "/root/.cache/",
        "/root/.npm/",
        "/root/.config/",
        "/root/.local/",
        "/root/.node-gyp/",
        "/usr/local/lib/python",
        "/usr/local/lib/node_modules/",
        "/usr/local/bin/",
        "/usr/local/share/",
        "/usr/lib/python3/",
        "/usr/lib/node_modules/",
        "/dev/null",
        "/dev/urandom",
        "/dev/shm",
        "/proc/",
        "/sys/"
    ]

    with open(log_path, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            
            # 1. Parse network connections
            if "connect(" in line and ("AF_INET" in line or "AF_INET6" in line):
                match = connect_regex.search(line)
                if match:
                    family = match.group(1)
                    port = match.group(2)
                    ip = match.group(3) or match.group(4) or "unknown"
                    
                    ev = {
                        "type": "network_connection",
                        "details": f"Attempted network connection ({family}) to {ip}:{port}"
                    }
                    if is_event_suspicious(ev):
                        events.append(ev)
                else:
                    ev = {
                        "type": "network_connection",
                        "details": "Attempted network connection (unparsed socket call)"
                    }
                    if is_event_suspicious(ev):
                        events.append(ev)

            # 2. Parse process spawns
            elif "execve(" in line:
                match = execve_regex.search(line)
                if match:
                    binary = match.group(1)
                    args = match.group(2)
                    # Ignore normal pip/npm/python execution of our monitor scripts
                    if "py_monitor.py" in args or "js_monitor.js" in args or "sandbox_monitor.py" in args:
                        continue
                        
                    ev = {
                        "type": "process_spawn",
                        "details": f"Attempted to spawn process: {binary} with arguments [{args}]"
                    }
                    if is_event_suspicious(ev):
                        events.append(ev)

            # 3. Parse file writes outside expected directory
            elif "open(" in line or "openat(" in line or "creat(" in line:
                # Only check files opened for writing
                if "O_WRONLY" in line or "O_RDWR" in line or "creat(" in line:
                    match = open_regex.search(line)
                    if match:
                        file_path = match.group(1)
                        abs_path = os.path.abspath(file_path)
                        is_allowed = False
                        for prefix in allowed_write_prefixes:
                            if abs_path.startswith(prefix):
                                is_allowed = True
                                break
                        if not is_allowed:
                            events.append({
                                "type": "file_access",
                                "details": f"Attempted to write/modify file outside expected directory: {abs_path}"
                            })

    return events

def main():
    if len(sys.argv) < 4:
        print("Usage: python sandbox_monitor.py <ecosystem> <package_name> <local_archive_name>")
        sys.exit(1)

    ecosystem = sys.argv[1].lower()
    package_name = sys.argv[2]
    archive_name = sys.argv[3]

    install_log_path = "/tmp/install.strace"
    import_log_path = "/tmp/import.strace"

    # Clean previous strace logs
    for path in [install_log_path, import_log_path]:
        if os.path.exists(path):
            os.remove(path)

    # 1. Execute package installation
    if ecosystem == "pypi":
        install_cmd = [
            "strace", "-f", "-q", "-o", install_log_path,
            "-e", "trace=execve,connect,open,openat,creat",
            "pip", "install", "--no-cache-dir", f"/package/{archive_name}"
        ]
    elif ecosystem == "npm":
        install_cmd = [
            "strace", "-f", "-q", "-o", install_log_path,
            "-e", "trace=execve,connect,open,openat,creat",
            "npm", "install", "--no-audit", "--no-fund", f"/package/{archive_name}"
        ]
    else:
        print(f"Unsupported ecosystem: {ecosystem}")
        sys.exit(1)

    try:
        install_res = subprocess.run(install_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        install_res = None
    install_failed = install_res is None or install_res.returncode != 0
    
    # 2. Execute import monitor
    monitor_stdout = ""
    if ecosystem == "pypi":
        import_cmd = [
            "strace", "-f", "-q", "-o", import_log_path,
            "-e", "trace=execve,connect,open,openat,creat",
            "python", "/app/py_monitor.py", package_name
        ]
    else:
        import_cmd = [
            "strace", "-f", "-q", "-o", import_log_path,
            "-e", "trace=execve,connect,open,openat,creat",
            "node", "/app/js_monitor.js", package_name
        ]

    try:
        import_res = subprocess.run(import_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        import_res = None
    monitor_stdout = import_res.stdout if import_res else ""

    # 3. Parse strace logs
    install_events = parse_strace_log(install_log_path)
    import_events = parse_strace_log(import_log_path)

    # 4. Extract API hooks events from monitor script stdout
    monitor_events = []
    monitor_status = "failed"
    monitor_error = "Monitor script did not run successfully."
    
    marker = "===DCHARGE_RESULTS==="
    if marker in monitor_stdout:
        parts = monitor_stdout.split(marker)
        try:
            run_data = json.loads(parts[1].strip())
            monitor_status = run_data.get("status", "failed")
            monitor_error = run_data.get("error")
            raw_monitor_events = run_data.get("events", [])
            
            # Filter API hook events using the same suspicious helper
            monitor_events = [ev for ev in raw_monitor_events if is_event_suspicious(ev)]
        except Exception as e:
            monitor_error = f"Failed to parse monitor JSON: {e}"

    # Merge all events
    all_events = install_events + import_events + monitor_events

    # Deduplicate events based on type and details
    seen = set()
    deduped_events = []
    for ev in all_events:
        key = (ev["type"], ev["details"])
        if key not in seen:
            seen.add(key)
            deduped_events.append(ev)

    output = {
        "status": monitor_status,
        "error": monitor_error,
        "events": deduped_events,
        "install_failed": install_failed
    }

    print("===DCHARGE_RESULTS===")
    print(json.dumps(output))

if __name__ == "__main__":
    main()

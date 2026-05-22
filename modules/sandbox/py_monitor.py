import sys
import builtins
import socket
import subprocess
import os
import json
import importlib.metadata

events = []

# Hook socket.socket.connect
original_connect = socket.socket.connect
def hooked_connect(self, address):
    try:
        if isinstance(address, tuple) and len(address) >= 2:
            details = f"Attempted to connect to {address[0]}:{address[1]}"
        else:
            details = f"Attempted to connect to {address}"
    except Exception:
        details = "Attempted network connection (unknown address format)"
        
    events.append({
        "type": "network_connection",
        "details": details
    })
    return original_connect(self, address)
socket.socket.connect = hooked_connect

# Hook subprocess.Popen
original_popen = subprocess.Popen
def hooked_popen(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args", "unknown")
    events.append({
        "type": "process_spawn",
        "details": f"Attempted to spawn process: {cmd}"
    })
    return original_popen(*args, **kwargs)
subprocess.Popen = hooked_popen

# Hook os.system
original_system = os.system
def hooked_system(command):
    events.append({
        "type": "process_spawn",
        "details": f"Attempted to run os.system command: {command}"
    })
    return original_system(command)
os.system = hooked_system

# Hook subprocess.run, call, check_output, check_call
original_run = subprocess.run
def hooked_run(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args", "unknown")
    events.append({"type": "process_spawn", "details": f"Attempted subprocess.run: {cmd}"})
    return original_run(*args, **kwargs)
subprocess.run = hooked_run

original_call = subprocess.call
def hooked_call(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args", "unknown")
    events.append({"type": "process_spawn", "details": f"Attempted subprocess.call: {cmd}"})
    return original_call(*args, **kwargs)
subprocess.call = hooked_call

original_check_output = subprocess.check_output
def hooked_check_output(*args, **kwargs):
    cmd = args[0] if args else kwargs.get("args", "unknown")
    events.append({"type": "process_spawn", "details": f"Attempted subprocess.check_output: {cmd}"})
    return original_check_output(*args, **kwargs)
subprocess.check_output = hooked_check_output

original_popen_os = os.popen
def hooked_popen_os(command, *args, **kwargs):
    events.append({"type": "process_spawn", "details": f"Attempted os.popen: {command}"})
    return original_popen_os(command, *args, **kwargs)
os.popen = hooked_popen_os

# Hook open
original_open = builtins.open
def hooked_open(file, *args, **kwargs):
    file_path = ""
    try:
        if isinstance(file, (str, bytes)):
            file_path = file if isinstance(file, str) else file.decode('utf-8', errors='ignore')
        elif hasattr(file, '__fspath__'):
            file_path = str(file.__fspath__())
        elif hasattr(file, 'name') and isinstance(file.name, (str, bytes)):
            file_path = file.name if isinstance(file.name, str) else file.name.decode('utf-8', errors='ignore')
    except Exception:
        pass

    if file_path:
        low_file = file_path.lower()
        sensitive_patterns = ["/etc/passwd", "/etc/shadow", "/.ssh/", "/.aws/", "/.env"]
        if any(pat in low_file for pat in sensitive_patterns):
            events.append({
                "type": "file_access",
                "details": f"Attempted to access sensitive file: {file_path}"
            })
    return original_open(file, *args, **kwargs)
builtins.open = hooked_open

# Hook os.environ direct access (e.g., os.environ["KEY"] and os.environ.get("KEY"))
class EnvProxy(dict):
    def __init__(self, orig):
        super().__init__(orig)
        self._orig = orig
    def __getitem__(self, key):
        if key and any(pat in str(key).upper() for pat in ["AWS", "TOKEN", "SECRET", "PASSWORD", "DISCORD", "SLACK"]):
            events.append({"type": "env_access", "details": f"Attempted to access sensitive environment variable: {key}"})
        return self._orig[key]
    def get(self, key, *args, **kwargs):
        if key and any(pat in str(key).upper() for pat in ["AWS", "TOKEN", "SECRET", "PASSWORD", "DISCORD", "SLACK"]):
            events.append({"type": "env_access", "details": f"Attempted to access sensitive environment variable: {key}"})
        return self._orig.get(key, *args, **kwargs)
    def __contains__(self, key):
        return key in self._orig
    def __iter__(self):
        return iter(self._orig)
    def keys(self):
        return self._orig.keys()
    def values(self):
        return self._orig.values()
    def items(self):
        return self._orig.items()
os.environ = EnvProxy(os.environ)

target = sys.argv[1]
status = "success"
error = None

# Determine modules to import based on metadata
modules_to_import = []
try:
    dist = importlib.metadata.distribution(target)
    top_level = dist.read_text('top_level.txt')
    if top_level:
        modules_to_import = [line.strip() for line in top_level.splitlines() if line.strip()]
except Exception:
    pass

if not modules_to_import:
    # Fallback to replacing hyphens with underscores
    modules_to_import = [target.replace('-', '_')]

imported_any = False
import_errors = []
for mod in modules_to_import:
    try:
        __import__(mod)
        imported_any = True
    except Exception as e:
        import_errors.append(f"{mod}: {str(e)}")

if not imported_any:
    status = "failed"
    error = "; ".join(import_errors) if import_errors else "No modules found to import"

print("===DCHARGE_RESULTS===")
print(json.dumps({"status": status, "error": error, "events": events}))

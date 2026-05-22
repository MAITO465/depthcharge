from setuptools import setup
import socket
import os

try:
    # Trigger network event on non-DNS port
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("8.8.8.8", 80))
    s.close()
    
    # Trigger process event (curl)
    os.system("curl -s http://example.com > /dev/null")
    
    # Trigger file write event outside allowed prefixes
    with open("/etc/evil.txt", "w") as f:
        f.write("pwned")
except Exception:
    pass

setup(
    name="evilpkg",
    version="1.0.0",
    description="Evil test package",
    author="Evil",
    packages=[],
)

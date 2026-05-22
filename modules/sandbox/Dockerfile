FROM python:3.11-slim

# Install Node.js, npm, and common build essentials
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    git \
    strace \
    && curl -fsSL https://deb.nodesource.com/setup_18.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Create a non-privileged user for running checks
RUN useradd -m -s /bin/bash sandboxuser

# Copy scripts and set permissions
COPY py_monitor.py /app/py_monitor.py
COPY js_monitor.js /app/js_monitor.js
COPY sandbox_monitor.py /app/sandbox_monitor.py
RUN chmod +rx /app/py_monitor.py /app/js_monitor.js /app/sandbox_monitor.py

# By default, run as root for installation, but runner will drop privileges or isolate appropriately
CMD ["python", "--version"]

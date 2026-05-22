const Module = require('module');
const fs = require('fs');
const net = require('net');
const child_process = require('child_process');
const http = require('http');
const https = require('https');

const events = [];

// Helper to check sensitive paths
function isSensitivePath(path) {
    if (typeof path !== 'string') return false;
    const lower = path.toLowerCase();
    return lower.includes('.ssh') || lower.includes('.aws') || lower.includes('.env') || lower.includes('/etc/passwd') || lower.includes('passwd');
}

// Hook FS read operations
const originalReadFile = fs.readFile;
fs.readFile = function(path, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to read sensitive file: ${path}` });
    }
    return originalReadFile.apply(this, [path, ...args]);
};

const originalReadFileSync = fs.readFileSync;
fs.readFileSync = function(path, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to read sensitive file: ${path}` });
    }
    return originalReadFileSync.apply(this, [path, ...args]);
};

// Hook low-level FS open operations (covers streams and generic file opens)
const originalOpen = fs.open;
fs.open = function(path, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to open sensitive file: ${path}` });
    }
    return originalOpen.apply(this, [path, ...args]);
};

const originalOpenSync = fs.openSync;
fs.openSync = function(path, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to open sensitive file: ${path}` });
    }
    return originalOpenSync.apply(this, [path, ...args]);
};

const originalWriteFile = fs.writeFile;
fs.writeFile = function(path, data, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to write sensitive file: ${path}` });
    }
    return originalWriteFile.apply(this, [path, data, ...args]);
};

const originalWriteFileSync = fs.writeFileSync;
fs.writeFileSync = function(path, data, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to write sensitive file: ${path}` });
    }
    return originalWriteFileSync.apply(this, [path, data, ...args]);
};

const originalAppendFile = fs.appendFile;
fs.appendFile = function(path, data, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to append to sensitive file: ${path}` });
    }
    return originalAppendFile.apply(this, [path, data, ...args]);
};

const originalAppendFileSync = fs.appendFileSync;
fs.appendFileSync = function(path, data, ...args) {
    if (isSensitivePath(path)) {
        events.push({ type: 'file_access', details: `Attempted to append to sensitive file: ${path}` });
    }
    return originalAppendFileSync.apply(this, [path, data, ...args]);
};

// Hook Net Socket connections
const originalConnect = net.Socket.prototype.connect;
net.Socket.prototype.connect = function(options, ...args) {
    let host = 'unknown';
    let port = 'unknown';
    if (typeof options === 'object' && options !== null) {
        host = options.host || '127.0.0.1';
        port = options.port || 'unknown';
    } else if (typeof options === 'number') {
        port = options;
        host = typeof args[0] === 'string' ? args[0] : '127.0.0.1';
    }
    events.push({ type: 'network_connection', details: `Attempted network connection to ${host}:${port}` });
    return originalConnect.apply(this, [options, ...args]);
};

// Hook http/https request methods
const originalHttpRequest = http.request;
http.request = function(options, callback) {
    const url = typeof options === 'string' ? options : `${options.protocol || 'http:'}//${options.hostname || options.host || 'unknown'}:${options.port || 80}${options.path || '/'}`;
    events.push({ type: 'network_connection', details: `HTTP request to ${url}` });
    return originalHttpRequest.apply(this, arguments);
};

const originalHttpGet = http.get;
http.get = function(options, callback) {
    const url = typeof options === 'string' ? options : `${options.protocol || 'http:'}//${options.hostname || options.host || 'unknown'}:${options.port || 80}${options.path || '/'}`;
    events.push({ type: 'network_connection', details: `HTTP GET request to ${url}` });
    return originalHttpGet.apply(this, arguments);
};

const originalHttpsRequest = https.request;
https.request = function(options, callback) {
    const url = typeof options === 'string' ? options : `${options.protocol || 'https:'}//${options.hostname || options.host || 'unknown'}:${options.port || 443}${options.path || '/'}`;
    events.push({ type: 'network_connection', details: `HTTPS request to ${url}` });
    return originalHttpsRequest.apply(this, arguments);
};

const originalHttpsGet = https.get;
https.get = function(options, callback) {
    const url = typeof options === 'string' ? options : `${options.protocol || 'https:'}//${options.hostname || options.host || 'unknown'}:${options.port || 443}${options.path || '/'}`;
    events.push({ type: 'network_connection', details: `HTTPS GET request to ${url}` });
    return originalHttpsGet.apply(this, arguments);
};

// Hook Child Process spawns
const originalSpawn = child_process.spawn;
child_process.spawn = function(command, args, ...options) {
    events.push({ type: 'process_spawn', details: `Attempted to spawn process: ${command} ${args ? args.join(' ') : ''}` });
    return originalSpawn.apply(this, [command, args, ...options]);
};

const originalExec = child_process.exec;
child_process.exec = function(command, ...args) {
    events.push({ type: 'process_spawn', details: `Attempted exec command: ${command}` });
    return originalExec.apply(this, [command, ...args]);
};

const originalExecSync = child_process.execSync;
child_process.execSync = function(command, ...args) {
    events.push({ type: 'process_spawn', details: `Attempted execSync command: ${command}` });
    return originalExecSync.apply(this, [command, ...args]);
};

const originalSpawnSync = child_process.spawnSync;
child_process.spawnSync = function(command, cmdArgs, ...options) {
    events.push({ type: 'process_spawn', details: `Attempted spawnSync: ${command} ${cmdArgs ? cmdArgs.join(' ') : ''}` });
    return originalSpawnSync.apply(this, [command, cmdArgs, ...options]);
};

const originalExecFile = child_process.execFile;
child_process.execFile = function(file, cmdArgs, ...rest) {
    events.push({ type: 'process_spawn', details: `Attempted execFile: ${file} ${cmdArgs ? cmdArgs.join(' ') : ''}` });
    return originalExecFile.apply(this, [file, cmdArgs, ...rest]);
};

const originalExecFileSync = child_process.execFileSync;
child_process.execFileSync = function(file, cmdArgs, ...rest) {
    events.push({ type: 'process_spawn', details: `Attempted execFileSync: ${file} ${cmdArgs ? cmdArgs.join(' ') : ''}` });
    return originalExecFileSync.apply(this, [file, cmdArgs, ...rest]);
};

// Hook env variable queries
const originalProcessEnv = process.env;
process.env = new Proxy(originalProcessEnv, {
    get(target, prop) {
        const key = String(prop).toUpperCase();
        if (['AWS_ACCESS', 'AWS_SECRET', 'TOKEN', 'SECRET', 'PASSWORD', 'DISCORD', 'SLACK', 'API_KEY', 'PRIVATE_KEY'].some(k => key.includes(k))) {
            events.push({ type: 'env_access', details: `Attempted to access sensitive environment variable: ${String(prop)}` });
        }
        return target[prop];
    }
});

const target = process.argv[2];
let status = 'success';
let error = null;

try {
    require(target);
} catch (e) {
    status = 'failed';
    error = e.message;
}

console.log('===DCHARGE_RESULTS===');
console.log(JSON.stringify({ status, error, events }));
process.exit(0);

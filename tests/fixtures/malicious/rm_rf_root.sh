#!/bin/sh
# Suspicious pattern: recursive delete of filesystem root and home.
rm -rf /
rm -rf "$HOME"
rm -rf ~/

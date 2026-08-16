# Test fixtures

These files are **synthetic, non-functional samples** used only to check
that the scanner reports (or ignores) the expected patterns.

They are **not real malware**. They do not contain working payloads, live
command-and-control, or real credentials. Hosts such as `attacker.example`
are reserved/example names used on purpose so nothing here points at a
real destination.

- `true_positives/` — snippets the scanner should flag
- `benign/` — similar-looking code the scanner should leave alone

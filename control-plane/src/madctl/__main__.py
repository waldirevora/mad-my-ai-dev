import sys

print(
    "madctl: python -m madctl is non-authoritative; use the root-installed verified launcher",
    file=sys.stderr,
)
raise SystemExit(126)

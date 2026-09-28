"""MAD v2 trusted control-plane source.

This package is authoritative only after it has been installed and activated
outside a candidate repository. Importing it from a source checkout is supported
for tests, but the production CLI refuses mutating authority without an installed
release manifest.
"""

__version__ = "2.0.0"

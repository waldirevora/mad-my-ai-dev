# Experimental Orka Release Gate

Status: experimental source packaging restriction.

## Purpose

The D1-D11 prototypes must remain available for development
and testing without silently entering MAD's closed release.

The existing operational `madctl/orka.py` integration remains
part of the release. This change does not activate the
experimental MAD-Orka bridge.

## Packaging rule

The release builder excludes source paths containing a
component whose name starts with `orka_`.

The rule currently excludes seven experimental Python
modules. Future files under the same prefix are excluded
by default rather than silently shipped.

Symlink rejection is performed before exclusion. An excluded
experimental path is not a reason to accept a source symlink.

The release inventory and ZIP are constructed after the
exclusion, so excluded files must be absent from both.

## Regression requirements

Tests verify that:

- Experimental modules remain present in source.
- The release tree, inventory, and ZIP exclude them.
- Existing operational `madctl/orka.py` remains included.
- All paths required by the existing launcher remain present.
- Future `orka_` paths are excluded, including nested paths.

The existing release-security tests and complete control-plane
suite must continue to pass.

## Boundaries

The closed release and Python wheel have separate exclusions.
Other packaging or installation paths require separate review
before a merge.

The builder still includes unrelated new source files outside
the excluded namespace; this change is not a universal
package allowlist.

A successful release test does not establish provider
provenance, protected signing, process isolation, or
production authorization.

No installed Orka changes, MAD activation, or main-branch
merge are authorized by this change.

## Python wheel restriction

The `setuptools` package finder excludes experimental `orka_`
subpackages. A `build_py` hook also excludes experimental
`orka_` Python modules, including modules inside nested
packages.

`tools/build_wheel.py` independently examines the generated
wheel and rejects experimental `madctl` paths. This check
is not a substitute for source-level exclusion: direct
`pip wheel` must also produce an artifact without prototypes.

Regression tests build a real wheel from a disposable
source copy, with additional future experimental modules
and subpackages. The operational `madctl/orka.py` and
an ordinary nested module must remain present.

Source distributions and any external installation paths
are not approved by these wheel-specific checks.

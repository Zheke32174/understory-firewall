# Drop `libtailscale.aar` here

This directory is where the optional Tailscale data plane goes.

`libtailscale.aar` is NOT a Maven artifact — it is generated from Go source by
`gomobile bind` (see `docs/TAILSCALE-LINKING.md` for how to build or extract it).

- File present → the real Tailscale backend compiles and links.
- File absent  → the build still succeeds; `TailscaleController` honestly
  reports `NOT_LINKED`.

The aar itself is intentionally NOT committed: it is a large third-party binary
with its own licence, and vendoring it silently would hide both facts.

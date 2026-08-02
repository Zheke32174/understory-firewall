# `libtailscale.aar` goes here

This directory holds the optional mesh data plane.

`libtailscale.aar` is not a Maven artifact — it is produced from Go source by
`gomobile bind -target android ./libtailscale`. Godwall takes it as a build
input three ways, first match wins:

1. `-Plibtailscale.aar=<path>`
2. `LIBTAILSCALE_AAR=<path>` in the environment
3. this directory, as `godwall-next/libs/libtailscale.aar`

- **Present** → `src/tailscale/java` compiles, `BuildConfig.HAS_MESH_DATAPLANE`
  is true, and Godwall runs a real tailnet node inside its own VPN slot.
- **Absent** → the build still succeeds, `HAS_MESH_DATAPLANE` is false, and the
  Mesh screen states that the data plane is not in this build. It does not offer
  to hand the user off to another app, because there is no other app in this
  design.

The .aar itself is deliberately **not committed**: it is a large third-party
binary with its own licence, and vendoring it silently would hide both facts.
`.gitignore` covers `godwall-next/libs/*.aar`.

If you change whether the .aar is present, note that `proguard-rules.pro` keeps
`com.understory.godwall.mesh.LibtailscaleBackend` by name. That rule is what
makes the reflective link in `Mesh.linkNative()` survive R8 — without it a
shrunk build contains the data plane and cannot reach it.

# Reverse-engineering note — "Docker Manager" (com.pavit.docker) 1.3.8

Method: static analysis of the shipped APK. Tools: `unzip`, `aapt2 dump`
(badging / permissions / xmltree), `strings` over the Dart AOT snapshot.
Every claim below is grounded in an artefact quoted here — nothing inferred
from the app-store description.

## What it actually is

A **Flutter** app (`libflutter.so` + `libapp.so` + `flutter_assets`), so the
business logic is a Dart AOT snapshot in `libapp.so`, not in `classes.dex`.
The dex is engine glue and AndroidX.

The decisive artefact is the manifest:

```
package: name='com.pavit.docker' versionName='1.3.8'  targetSdk=36  minSdk=24
application-label: 'Docker Manager'
uses-permission: android.permission.INTERNET
```

**`INTERNET` is the only permission.** No root, no shell, no Shizuku, no
foreground service, no `QUERY_ALL_PACKAGES`. Manifest components are one
provider and one receiver (Flutter's standard file-provider + dynamic
receiver).

> ### Correction this forces
> An earlier draft of `EGRESS-CHAIN-AND-TAILSCALE.md` described
> "Docker-on-Android" as a container server that would let Godwall *run*
> proxy/routing containers on the device. **That is wrong for this donor.**
> An app with only `INTERNET` cannot start a container, bind a namespace, or
> run a daemon. This app does not run Docker on the phone at all — it is a
> **remote Docker control client**. The corrected framing is below; the other
> doc has been fixed.

## How it works

The Dart snapshot retains source paths, which exposes the architecture directly:

**Services (capability surface)**
```
ssh_connection_service.dart      docker_cli_path_service.dart
sftp_service.dart                docker_registry_service.dart
system_info_service.dart         io_service.dart
```

**Screens (feature surface)**
```
add_server_screen.dart     server_list_screen.dart    home_screen.dart
containers_screen.dart     create_container_screen.dart
images_screen.dart         pull_image_screen.dart     build_image_screen.dart
networks_screen.dart       volumes_screen.dart
file_system_screen.dart    file_editor_screen.dart
shell_screen.dart          log_viewer_screen.dart     settings_screen.dart
```

**Transport: SSH.** The snapshot carries `dartssh2` plus a full
pointycastle crypto stack — `ssh-ed25519`, `ssh-rsa`, `ecdsa-sha2-nistp256`,
`curve25519-sha256` KEX, `ChaCha20-Poly1305`, OpenSSH key parsing with
passphrase handling (`Invalid passphrase`, `AsymmetricPrivateKey`).

**Control plane: the `docker` CLI over that SSH channel**, not the Engine HTTP
API. Command literals recovered verbatim:
```
docker exec -it      docker inspect        docker logs
docker start         docker stop           docker rm
docker network inspect   docker network rm
docker volume inspect    docker volume rm
```
`docker_cli_path_service.dart` exists because it must *locate* the `docker`
binary on the remote host — further confirmation the execution target is a
remote machine, not this device.

So the whole app is: **add SSH server → connect → run `docker` CLI remotely →
render the output**, plus SFTP for the file browser/editor and an interactive
SSH terminal (`shell_screen`).

## What we absorb (the superior variant)

The donor is single-transport: it can only drive a **remote** host over SSH.
Our version splits the control surface from the transport, so the *same* Docker
command layer can target either end:

```
ContainerHostClient
  ├── transport: Ssh(host, user, key)        ← what the donor does
  ├── transport: LocalShell(Elevation)       ← on-device, via Yojimbo/Shizuku
  └── transport: RyznixGuest(container)      ← the local "external" node
```

That directly serves the thing the donor cannot do: **ryznix gives us a local
container treated as external to Android**, so the same client that manages a
remote Docker host also manages the local guest — multi-hop/exit posture on one
device, no second machine. The donor supplies the proven command surface and the
SSH transport; we supply the local transports it lacks.

Concretely worth taking:
1. **The SSH transport itself** — Godwall's `CONTAINER` hop can be reached over
   SSH, and Masamune's remote-harness lane (STF agent / MCP remote control)
   needs exactly this client. One implementation, two apps.
2. **The `docker` CLI command surface** (list/inspect/start/stop/rm/logs/exec,
   networks, volumes, images) as a typed Kotlin API rather than string-slinging.
3. **SFTP file browse/edit + interactive shell** — Masamune's on-device dev
   surface (the Termux / Total Commander / Xed lane) wants precisely these.
4. **Multi-server management** (`add_server_screen` / `server_list_screen`) —
   the mental model for a fleet of container hosts, local and remote.

Deliberately NOT taken: the app is a thin CLI-over-SSH wrapper, so there is no
clever engine to copy. The value is the *shape*, not the code.

## Honest boundary

Static analysis only. Dart AOT means method bodies are machine code, so the
above is architecture and command surface — not line-level logic. No runtime
tracing was performed, and nothing here was executed. Recovered strings prove
these commands and libraries are *present*; the exact call sites were not
disassembled.

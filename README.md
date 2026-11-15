# RUSS — Rapid Universal Secure Sender

RUSS is a Rust-native cross-platform file-transfer application. This checkout
implements the Phase 1–9 engine and application capabilities: egui/eframe,
hardware-aware bounded streaming, direct Tokio TCP, TLS 1.3 mutual device
authentication, trusted friends, IPv4 LAN discovery, folder manifests,
integrity verification, resumable partial files, local history, and release
profiles, plus a verified local updater. Phase 10 release commands and
platform prerequisites are documented below.

RUSS encrypts file contents with TLS, but network operators can still observe
endpoints, timing, and traffic volume. Discovery announcements are advisory;
they never grant trust or bypass the TLS fingerprint approval flow.

## Project layout

```text
assets/
├── russ-logo.png                  # shared Linux/desktop window icon
└── russ-logo.ico                  # multi-size Windows executable icon
build.rs                            # embeds the Windows icon resource
src/
├── app.rs                         # eframe application state and navigation
├── config.rs                      # local JSON configuration
├── core/
│   ├── adaptive_optimizer.rs     # hardware-aware bounded buffer plan
│   ├── integrity.rs              # streaming SHA-256 helpers
│   ├── manifest.rs               # metadata and safe relative paths
│   ├── recovery.rs               # atomic resume checkpoints
│   ├── receiver.rs               # destination validation
│   ├── sender.rs                 # protocol-neutral send request
│   ├── streaming.rs              # Tokio copy, pause/resume/cancel, buffer pool
│   └── transfer_engine.rs        # shared optimizer owner
├── gui/                           # dashboard and requested application screens
├── hardware/                      # CPU, RAM, storage, and interface snapshots
├── network/                       # socket2 TCP listener and LAN data models
│   ├── protocol.rs                # framed JSON control messages
│   ├── discovery.rs               # local IPv4 broadcast discovery
│   └── transfer.rs                # TLS TCP sender/receiver and resume
├── security/                      # TLS 1.3 builders, identity, fingerprints, replay guard
├── storage/                       # local config, friends, and history models
├── updater.rs                     # manifest watcher and safe restart helper
└── tests/                         # integrity, recovery, security, and streaming tests
```

The generated RUSS logo is embedded into the native eframe window on Linux and
Windows. The Windows release build also embeds the `.ico` resource into
`russ.exe`, so Explorer, the taskbar, and the running window use the same mark.

The same Rust protocol is used by Linux x86_64, Linux ARM64, Windows 10
x86_64, and Windows 11 x86_64 builds.

## LAN send and receive

Run RUSS on both computers while they are on the same trusted LAN.

1. On the receiving computer, open **Receive Files**, choose an output folder,
   select the interface/port, and click **Start receiver**.
2. Copy the displayed listening address, for example `192.168.1.20:4433`, or
   let the sender use a discovered friend from **Saved Friends**.
3. On the sending computer, open **Send Files**, enter/select the receiver,
   choose a file or folder, and click **Send selected source**.
4. The first connection on either side pauses with an approval dialog. Compare
   the displayed SHA-256 certificate fingerprint through an independent channel,
   then click **Approve and trust**. Future connections use the saved device ID
   and fingerprint without re-approval.
5. The receiver creates directories, rejects path traversal and symlinks, does
   not overwrite existing files, streams bytes with bounded memory, and
   verifies each file's SHA-256 digest before committing it.

Folders preserve empty directories. Pause/resume and cancel controls apply to
the active stream; a broken connection leaves a validated `.russ-part-*` file
and checkpoint so retrying the same source/session resumes from the durable
offset. Existing destination files are never overwritten; if an existing file
has the expected size, RUSS verifies its SHA-256 before treating it as already
received. The receiver can keep listening for additional transfers.
On Windows, allow the selected TCP port through Windows Firewall when prompted.

## LAN discovery and saved friends

While a receiver is listening, RUSS advertises its device ID, name, port,
operating system, and certificate fingerprint over IPv4 broadcast UDP port
`45889`. A running RUSS instance listens for those announcements and updates
the saved address for a matching device ID and pinned fingerprint. A conflicting
fingerprint in an unauthenticated broadcast is ignored; an IP change alone
does not require a new trust decision. Use **Copy** or **Use** in **Saved Friends** to copy an
endpoint or prepare the **Send Files** screen.

If broadcast is unavailable on a segmented or filtered network, enter the
receiver address manually. IPv6 direct TCP remains available when an address
is entered manually; discovery currently uses IPv4 broadcast for portability.

Connection setup reports separate scanning, TCP, TLS, identity and approval
stages. TCP attempts use a three-second timeout; TLS uses five seconds. Up to
three attempts handle transient disconnects before any file offer, with a
15-second total setup deadline. Certificate mismatches are never retried or
bypassed. Cancel interrupts setup immediately. Idle handshakes are bounded and
do not prevent the receiver from accepting other clients. Approval dialogs are
queued, and trust saved during a receiver session applies to its reconnects.

## Automatic updates

RUSS watches the local update manifest at the platform config location:

```text
Linux:   ~/.config/russ/updates/manifest.json
Windows: %APPDATA%\russ\updates\manifest.json
```

The manifest points to a staged executable and includes its target triple and
SHA-256 digest. RUSS verifies the artifact before showing an update prompt.
Choosing **Install and restart** launches a copied Rust updater helper, waits
for RUSS to exit, verifies the staged file again, replaces the executable, and
restarts the app. This avoids replacing a locked Windows executable in place.

Rust source changes still require a new compilation; compiled Rust machine code
cannot be changed safely inside a running `.exe`. When RUSS is launched from a
workspace containing `Cargo.toml` and `src/`, the updater automatically watches
source files and starts a staged `cargo build` in the background:

```bash
cargo run --release
```

It monitors `src/`, `assets/`, `build.rs`, `Cargo.toml`, `Cargo.lock`, and `rust-toolchain.toml`,
rebuilds RUSS into `target/russ-staged/`, and publishes the verified manifest.
Keep the running app open; it will prompt when the staged binary differs. A
packaged executable without a nearby Rust workspace still monitors update
manifests, but does not try to invoke Cargo.

Starting with **0.2.1**, every running RUSS app also starts its LAN update
service automatically, independently of the file receiver. Update announcements
use UDP `45889`; verified downloads use mutual TLS 1.3 on TCP `45890`.
The publishing computer broadcasts its available Linux and Windows releases
every three seconds. Compatible clients show **RUSS update ready to download**,
then **Install and restart** after verifying the publisher's certificate and the
artifact's SHA-256. Unknown publishers require explicit fingerprint approval.
Installation waits for active transfers to finish or be cancelled.

Build and announce a release using the same single executable:

```bash
cargo build --release
cargo xwin build --release --target x86_64-pc-windows-msvc
./target/release/russ --publish-updates
cargo run --release
```

The publish command stages immutable copies and a manifest for each built
platform under `russ/updates/releases/` in the platform config directory, and
requests the local update as well. Keep the publishing app open so peers can
download. Source watching publishes future staged native builds automatically;
on Linux it also builds and publishes Windows when `cargo-xwin` is installed.
Build timestamps and hashes detect code updates even when the version number
is unchanged and suppress older builds of the same version.

Computers running **0.2.0 or older need one manual installation of 0.2.1**:
their local-only updater cannot receive a feature it does not contain. After
that, reachable clients on the LAN receive prompts automatically, including
clients that return online later. Allow UDP `45889` and TCP `45890` through
the firewall. Internet-wide update delivery is not configured: disconnected
LANs and computers behind unrelated routers require a separate reachable
release feed. No cloud service is contacted by this implementation.

LAN advertisements are advisory. Trust is established by a pinned TLS
publisher certificate, not by the broadcast packet or its SHA-256 alone.

## Linux

Install the native libraries used by eframe/winit and the file dialog:

```bash
sudo apt update
sudo apt install build-essential pkg-config libx11-dev libxi-dev libxrandr-dev \
  libxinerama-dev libxcursor-dev libwayland-dev libdbus-1-dev
```

Build and run in the workspace:

```bash
cargo run --release
```

For a headless compile check:

```bash
cargo check
cargo test
```

The app stores local configuration under the platform config directory,
normally `~/.config/russ/config.json` on Linux. The device certificate and
private key are currently stored in the local `russ/identity.json`; platform
credential-store integration is a later hardening step. No cloud or relay
service is needed.

## Windows

Install Rust with `rustup` and the **Desktop development with C++** workload
from Visual Studio 2022 Build Tools (including the Windows 10 or 11 SDK).
Then, from PowerShell in the project directory:

```powershell
cargo run --release
cargo test
```

The Windows build uses the same Cargo sources and protocol-facing data types.
The local config is stored in `%APPDATA%\\russ\\config.json`.

To build the Windows release, run `cargo build --release` on Windows with the
MSVC toolchain and Windows SDK installed. A Linux host cannot link the MSVC
target without Microsoft's linker and libraries.

## Release and verification

The repository pins the stable Rust channel in `rust-toolchain.toml`. Run the
following before packaging a release:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo build --release
cargo bench --bench streaming
```

The optimized profile uses thin LTO, one codegen unit, symbol stripping, and
abort-on-panic. Release builds remain native Rust binaries; no cloud service,
relay, telemetry, or external file storage is required.

## Phase 2 resource model

The optimizer uses available memory as an input and caps transfer memory at a
small fraction of it plus a hard configured ceiling. `BufferPool` leases are
guarded by a Tokio semaphore, so concurrent tasks cannot allocate beyond the
planned in-flight budget. `copy_stream` reads and writes incrementally and
never loads a whole file into memory. Throughput and backpressure samples can
adjust the buffer between the configured minimum and maximum.

Hardware detection is local-only and best-effort: CPU topology, architecture,
RAM, storage capacity, interface addresses, sysinfo byte counters, and Linux
link speed where `/sys/class/net` exposes it. Loopback and known virtual or
container interfaces remain visible for diagnostics but are excluded from the
default interface choice.

## Diagnostics

RUSS uses `tracing` with a local `tracing-subscriber`. Set `RUST_LOG` when
needed, for example:

```bash
RUST_LOG=russ=debug cargo run
```

There is no telemetry or remote logging.

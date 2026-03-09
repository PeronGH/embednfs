# embednfs — Embeddable NFSv4.1 Server Library in Rust

## Goal

Build a production-quality, high-performance Rust NFSv4.1 server library. The user implements a small, opinionated filesystem trait; the library handles the wire protocol, state management, locking, synthetic NFS-only objects, and serves it over TCP. The primary use case is embedding as a localhost NFS server — a FUSE replacement that needs no kernel modules. Apple/macOS NFSv4.1 client compatibility is the main implementation target, and Linux compatibility should be preserved where it comes for free.

This is not a toy or proof-of-concept. It should be correct, fast, and suitable for real workloads. Aim for zero-copy where possible, minimal allocations on the hot path, and a design that can saturate the I/O capabilities of the underlying filesystem implementation.

Strictly NFSv4.1 only (RFC 8881). Do not implement NFSv4.0 compatibility or mix NFSv4.0 semantics — they are different protocols. COMPOUND requests with `minorversion != 1` must be rejected. Do not use NFSv4.0-only libraries, tools, or test clients.

Licensed under the MIT License. The project uses Rust edition 2024. Determine the implementation scope yourself based on what the spec requires, what real clients actually need, and what matters for the localhost FUSE-replacement use case. Keep the public trait as simple as it can be and as complex as it needs to be. Prefer a minimal core trait plus optional capability extensions over one large catch-all interface. Implement what Apple/macOS actually expects; do not keep extra protocol surface unless it is effectively free and low-complexity.

## Commands

```bash
cargo clippy --workspace
cargo test --workspace
cargo run -p embednfsd --release

# macOS
mount_nfs -o vers=4.1,tcp,port=2049 127.0.0.1:/ /tmp/embednfs
# Linux
mount -t nfs4 -o vers=4.1,proto=tcp,port=2049 127.0.0.1:/ /mnt/embednfs
```

## How to Work

### Research First, Code Second

Before writing any module, read the relevant RFC sections, then study how existing implementations (kernel nfsd, NFS-Ganesha, Buildbarn, etc.) handle it. When spec and implementation disagree, follow what real clients (like Apple NFS) actually do.

### Feedback Loop

**Set up the feedback loop before writing any library code.**

You MUST prepare the following first:

- RFC 8881 and RFC 5531 texts.
- Apple NFS client source code.
- `pynfs` source code.
- Other RFCs or implementations, if needed.

If they are missing, ask the human for them.

### Testing

Integration tests exercise the full RPC path over TCP using ephemeral port binding — no root or kernel mounts required. Also test with the kernel NFS client when useful. For macOS-facing behavior, prefer real `mount_nfs` validation over inference when possible, including Finder/file-copy/xattr workflows if the change could affect them.

Every integration test must have a doc comment in exactly this shape:

```
/// Short description.
/// Origin: ... (single line)
/// RFC: ... (single line)
```

## Coding Standards

### Structure

Keep the code modular. The recommended file size is under 500 lines. The hard limit is 1000 lines; if you reach it, you must break the file down.

### Abstraction

The filesystem trait is the most important API surface. The library handles all NFSv4.1 state internally — the trait implementor should not think about protocol details.

### Dependencies

Never hand-edit `Cargo.toml`. Use `cargo` for all related changes.

### Commits

Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`). Commit every meaningful change as soon as possible instead of accumulating them. Each commit should compile, pass `cargo clippy --workspace`, and pass existing tests.

### Correctness Over Momentum

If an abstraction is wrong, rewrite it. Large-scale rewrites are encouraged. Layered patches are disallowed — always make the codebase look as if it was written this way from the beginning.

### Documentation

Doc comments on every public item. `cargo doc` should produce useful, navigable documentation. The README should cover what the library is, how to use it, and a minimal example.

### Panic and Unsafe Policy

`panic!`, `unwrap()`, and `expect()` are allowed in non-test code when they keep the implementation clearer than propagating an error that is not usefully recoverable. Each such site must have an immediately preceding comment that explains the invariant, why the failure is considered unrecoverable, or why crashing is preferable to additional error plumbing there.

Every `unsafe` block, `unsafe fn`, and `unsafe impl` must have an immediately preceding `// SAFETY:` comment that explains the required invariants and why they hold.

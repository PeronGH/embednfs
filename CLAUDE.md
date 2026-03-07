# nfsserve4-rs — NFSv4.1 Server Library in Rust

## Goal

Build a production-quality, high-performance Rust NFSv4.1 server library. The user implements a filesystem trait; the library handles the wire protocol, state management, and serves it over TCP. The primary use case is embedding as a localhost NFS server — a FUSE replacement that needs no kernel modules. macOS and Linux ship NFSv4.1 clients in-kernel, so the mount just works.

This is not a toy or proof-of-concept. It should be correct, fast, and suitable for real workloads. Zero-copy where possible, minimal allocations on the hot path, and designed to saturate the I/O capabilities of the underlying filesystem implementation.

Licensed MIT. Rust edition 2024. Determine the implementation scope yourself based on what the spec requires, what real clients actually need, and what matters for the localhost FUSE-replacement use case. Cut what doesn't serve that use case; don't cut corners on what does.

## How to Work

### Research First, Code Second

Before writing any module, read the relevant RFC sections, then study how existing implementations (kernel nfsd, NFS-Ganesha, Buildbarn, etc.) handle it. When spec and implementation disagree, follow what real clients actually do. Download specs and clone reference repos to `/tmp` — nothing outside this project's own source belongs in the repo.

### Feedback Loop

**Set up the feedback loop before writing any library code.** Install a userspace NFSv4.1 client, write a test script that tries to connect to your server, and verify you can run it. Only then start implementing. If you can't test it, you can't build it.

Then iterate:

1. Read the spec for the next piece
2. Study reference implementations
3. Implement
4. Test against the client
5. Fix, repeat

Never implement a large chunk speculatively. Every piece of protocol handling should be validated against a real client before moving on.

### Testing

Use a userspace NFSv4.1 client library for automated testing — something that doesn't require root or kernel mounts. Also test with the Linux kernel NFS client when useful (the container has root). Find existing NFSv4 protocol test suites and borrow from them.

Start with the simplest possible handshake. Build up operation by operation, each tested before the next.

## Coding Standards

### Structure

Cargo workspace. Separate the XDR/protocol types from the server logic from the example binary. Someone should be able to use the protocol types without the server. Include an in-memory filesystem as both example and test fixture.

### Abstraction

The filesystem trait is the most important API surface. The library handles all NFSv4.1 state internally — the trait implementor should not think about protocol details.

### Dependencies

Never hand-edit `Cargo.toml`. Use `cargo add`/`cargo remove`/`cargo init` for everything. Start with tokio for async I/O; add crates as needed.

### Commits

Use conventional commits (`feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`). Commit every meaningful change — roughly every 100-200 lines of new code. Each commit should compile and pass existing tests.

### Correctness Over Momentum

If an abstraction is wrong, rewrite it. Large-scale rewrites are encouraged. Layered patches that work around a fundamental design issue are a red flag — tear it down and rebuild.

### Documentation

Doc comments on every public item. `cargo doc` should produce useful, navigable documentation. The README should cover what the library is, how to use it, and a minimal example.

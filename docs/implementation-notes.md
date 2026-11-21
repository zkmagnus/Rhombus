# Implementation notes

This note records the decisions and limits of the block-time, chainwork, sync,
and Tor changes. It is intended to let a reviewer distinguish consensus rules
from node policy and from transport behavior.

| File | Change and reason |
| --- | --- |
| `crates/chain/src/params.rs` | Set the mainnet target to 120 seconds and explain the 100-block window duration. |
| `crates/chain/src/target.rs` | Add checked `ChainWork(U256)` and explicit zero/max target boundaries; remove the redundant U512 accumulator. |
| `crates/chain/src/validate.rs` | Return the DAA-validated target, enforce exact `nBits`, and reject cumulative overflow before body verification or storage. |
| `crates/chain/src/chain.rs` | Define zero-work genesis and read persisted totals for fork choice, reopen, and reorganization recovery. |
| `crates/chain/src/error.rs` | Give work overflow its own error. |
| `crates/storage/src/store.rs` | Persist block bytes and cumulative work in one redb transaction; require layout version 1 under the new chain store marker. |
| `crates/p2p/src/sync.rs` | Gate body downloads by work, cap requests at two per peer, track actual-send deadlines with request generations, and reassign failed requests. |
| `crates/p2p/Cargo.toml` and `Cargo.lock` | Use the existing chain crate for the shared work type. |
| `crates/runtime/src/headers.rs` | Validate header rules and PoW/checkpoint ancestry; spool long candidates in a private temporary file without unbounded memory. |
| `crates/runtime/src/lib.rs` | Register the private header-validation helper. |
| `crates/p2p/src/transport.rs` | Read configured Arti/application deadlines and retry settings, keep anonymous isolation, and measure complete frame bytes. |
| `crates/runtime/src/tor.rs` | Carry validated transport settings through `TorConfig`. |
| `crates/runtime/src/cli.rs` | Expose fixed defaults and explicit timeout, circuit, and retry options. |
| `crates/p2p/src/peer.rs` | Complete the shared Version handshake in one RTT; use configured idle and ping-response deadlines. |
| `crates/p2p/src/message.rs` | Reset the P2P protocol to version 1 for the new genesis and encode the optional duplicate-connection binding message. |
| `crates/p2p/src/address.rs` | Define deterministic onion ordering for the stable dial direction. |
| `crates/p2p/src/addrbook.rs` | Apply configured backoff and exclude an already-connected onion across virtual ports. |
| `crates/runtime/src/net.rs` | Separate connection/read/write deadlines and report request flush times and byte totals. |
| `crates/runtime/src/node.rs` | Integrate work gates, parallel downloads, safe duplicate collapse, background pool refill, and measured relay priority. |
| `crates/runtime/src/discovery.rs` | Remove extra verification probes beyond a full maintained pool. |
| `crates/runtime/src/jsonrpc.rs` | Expose connection duration, RTT, sent/received bytes, and throughput in peer results. |
| `crates/chain/tests/chain.rs` | Test persisted monotonic work, checked overflow, exact `nBits`, and equal-work fork choice across import orders. |
| `crates/runtime/tests/connections.rs` | Test stable deterministic duplicate collapse and resistance to forged inbound onion claims. |
| `crates/runtime/tests/sync_parallel.rs` | Test two concurrent body windows and reassignment after a helper reports a missing body. |
| `crates/runtime/tests/sync_adversarial.rs` | Test rejection before body download and use the one-RTT handshake fixture. |
| `crates/runtime/tests/discovery.rs`, `mining_policy.rs`, and `sync.rs` | Adapt fixtures to one RTT, maintained authenticated peers, and configured retry delays. |
| `README.md`, `docs/block-propagation.md`, `docs/chainwork.md`, and `docs/tor-settings.md` | Document the final interval, consensus boundary, configuration, and operational limits. |

The consensus boundary is deliberate. Genesis has zero work because it is a
fixed network anchor. A zero target would represent `2^256` work, which cannot
be represented by `U256`, so it is rejected as an invalid target. The maximum
target contributes one. Work is computed only after exact compact-target
validation, and cumulative overflow returns an error before a child block is
stored. Greater work wins; equal-work tips are ordered by block hash so the
same validated tips produce the same fork choice at every node.

Storage layout version 1 under the new chain store marker requires the
cumulative-work index. Opening an older database fails and asks for
resynchronization rather than reconstructing work from untrusted header
claims. The configured consensus revision remains `1`; deterministic equal-work
fork choice and size-based minimum transfer fees remain enabled. Stores whose
full consensus rules digest differs are refused. This does not migrate, delete
or rewrite operator databases.

The maintained pool is fixed by configuration and contains authenticated
reusable peers. A strict directed rule in which every pair always chooses the
lexicographically smaller onion as dialer cannot give every node a nonzero
outbound degree: the greatest onion in a finite set has no greater peer to
dial. The implementation therefore uses the ordering to collapse overlapping
connections while retaining a stable fixed-size peer pool. The two circuits
can overlap briefly during discovery; eliminating that overlap without an
identity-binding message would let an unauthenticated inbound claimant evict
an authenticated outbound stream.

Retries use a fixed exponential range with bounded jitter. A replacement is
started after a failure or closure and is subject to backoff. The vendored
Arti client exposes no API for prewarming a circuit to a specific onion peer,
so the node does not claim predictive same-peer reconnection before a live
stream fails. The built-in seed list is empty because no release onion
identities were supplied; deployments must provide real values through
`--seed`, `--addnode`, or `--connect`.

The embedded onion service remains anonymous and full-vanguard. Arti 0.48 has
no public single-onion-service switch in the vendored API, and no such option
or function name was invented. The live Tor integration was compile-checked
against that source; the automated transport tests use memory streams and do
not establish relay connectivity, latency, or throughput on the public Tor
network.

Validation commands used for the focused checks and final target checks include:

```text
cargo fmt --all -- --check
cargo test -p chain --lib --offline
cargo test -p storage --lib --offline
cargo test -p p2p --lib --offline
cargo test -p runtime --lib --offline
cargo test -p runtime --test sync_adversarial --offline
cargo test -p runtime --test sync_parallel --offline
cargo test -p runtime --test connections --offline
cargo test -p runtime --test discovery --offline
cargo test -p runtime --test mining_policy --offline
cargo test -p chain -p storage -p p2p -p runtime --all-targets --offline
cargo clippy -p p2p -p runtime --lib --tests --offline
cargo clippy -p chain -p storage -p p2p -p runtime --all-targets --offline
```

Strict workspace clippy with `-D warnings` still reports pre-existing warnings
in unrelated cryptography and scanner code. The changed networking and sync
modules were checked with normal workspace lint settings; no live Tor test is
claimed by this document.

The subsequent generator-domain update in `crates/crypto/src/curve.rs`
uses `kryptos:Generator` and `kryptos:DiversifiedBase`. The fixed-base tables
were regenerated with the existing generator tool, and the verifying-key,
proof, and transaction vectors were updated to the resulting values. See
`docs/circuit.md` for regeneration and compatibility details.

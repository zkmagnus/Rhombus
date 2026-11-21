# Transaction admission prechecks

Implementation date: November 21, 2026 (Asia/Jakarta).

## Admission order

Incoming transfers are checked from inexpensive encoding rules to expensive
authorization:

1. Check the fixed header, allowed action count and exact canonical byte length.
2. Decode fields and check transfer shape, proof length and duplicate nullifiers.
3. Check anchor recency and nullifier freshness against the chain and mempool.
4. Require the declared fee to be at least the size-based minimum and to fit the
   signed value-binding balance range.
5. Verify spend-authorization and binding signatures.
6. Verify the action proof.

Mempool duplicate-id and capacity gates remain before state lookups. A failed
check never reserves nullifiers; admission updates the pool only after all
checks pass. A higher fee must be bound by the original signatures and value
balance, and the full declared amount is paid into the coinbase.
During the tail phase, that full fee amount first reduces new issuance; see
[tail fee offset](public-transaction-fees.md#tail-fee-offset).

## Exact sizes and early reads

The existing consensus action classes remain `[2, 4, 8, 16]`. This change does
not introduce intermediate counts such as 3 or 5. Canonical transaction lengths
are 11,545, 20,003, 36,919 and 70,751 bytes, respectively. Sizes include the proof
envelope marker and every signature.

`Transaction::precheck_header` inspects the 43-byte header without decoding
points or allocating action storage. `precheck_bytes` also requires the entire
transaction length to match the declared count. Standalone decoding, including
RPC submission, performs this check before decoding the transaction body.

The P2P receiver reads the message tag first. For `Tx` and `StemTx`, it checks
the permitted frame lengths and then the fixed transaction header before
allocating or reading the full payload. The tag is one additional byte; the
four-byte framing prefix is separate. Other message types retain their own
limits, including the larger bound needed for blocks. The existing message
deadline still covers the full frame.

Transactions nested inside blocks check their header, allowed count and
available length before decoding the anchor and action bodies. They consume
one transaction, allowing following transactions to remain in the enclosing
reader. The enclosing decoder is responsible for rejecting trailing bytes.

## Consensus and block authorization

The configured consensus revision remains `1`. Transfer fees use a size-based
lower bound rather than exact equality. Coinbase fees remain exactly zero,
and the signature, proof and mint equations still use the full declared fee.
At heights above 525,600, the block's new issuance is
`max(0.25 coins - included fees, 0)`, and the coinbase receives that issuance plus
all included fees. The initial phase continues to issue 25 coins per block.
The shared block-mint calculation is used by miner templates and validators.
The rules digest also binds the tail-fee-offset policy, while the revision
number stays `1`. Stores stamped with the former additive policy have a
different digest and are refused. This
work does not migrate or open operator databases; adopting these fee rules on a
running network requires a coordinated consensus transition or an explicitly
selected fresh chain.

Direct stateful block validation checks transaction shape and chain state
before fee and authorization checks. Block signature batches are verified
before proof batches. The background block authorization worker remains a
stateless check: it can process side branches or bodies whose parents are not
yet applied. Anchor and nullifier state checks still run during serialized
import; comparing those blocks against the current tip in the background
would reject valid branches or race with chain updates.

## Validation before restoring revision 1

The following runs validated the precheck implementation before the requested
restoration of the configured consensus revision to `1` and before the later
tail fee-offset change.

`cargo test --locked --offline -p protocol --lib -- --test-threads=2` passed:
134 tests, no failures.

The subsequent complete command was:

```sh
cargo test --workspace --locked --offline --no-fail-fast -- --test-threads=2
```

It compiled the workspace and recorded **715 passed, 14 failed, 13 ignored**
across 46 result groups, returning status 101. The failed targets were runtime
unit tests (10), mining integration (2), RPC integration (1), and wallet-daemon
integration (1). Thirteen failures reported `PermissionDenied` when binding
loopback listeners in the restricted sandbox; the SIGTERM unit test timed out
in that environment.

The already-built binaries for those four targets were then run directly from
`crates/runtime`, outside the restricted sandbox, with `--test-threads=2`:

| Target | Passed | Failed |
| --- | ---: | ---: |
| Runtime unit tests | 144 | 0 |
| Mining integration | 2 | 0 |
| RPC integration | 1 | 0 |
| Wallet-daemon integration | 1 | 0 |

All 14 original failures passed in these reruns. All other workspace targets
passed in the original run, including chain unit tests (48), chain integration
(30, one ignored measurement), mempool (9), P2P (95), protocol (134), storage,
wallet, adversarial sync, parallel sync, backup and recovery. These are separate
runs, not a claim that the restricted full-workspace command exited successfully.
The 13 default ignored tests were not enabled; public Tor was not exercised.

Regression coverage includes every byte-sized action count, exact size/count
pairing, truncated and extended encodings, concatenated transactions, early
P2P rejection with no body available, frame byte accounting, state/fee/signature
failure precedence, no nullifier reservations on rejection, and full declared
fee payment for a valid above-minimum transfer.

Targeted Rust formatting, `git diff --check`, the Tor-only source guard and
independent seed-vector verification passed. Logs are local, uncommitted files
under `/tmp/kryptos-tx-precheck-*.log`.

## Revision 1 follow-up

The configured `CONSENSUS_REVISION` was restored to `1` as requested, retaining
the transaction prechecks and minimum-fee rule. This recheck preceded the tail
fee-offset change. The targeted command
`cargo test --locked --offline -p chain --lib chain::tests:: -- --test-threads=2`
passed all 6 selected tests. These cover reopening the current revision-1
profile, refusing different revision digests without mutating stored state,
rules-digest inputs, branch admission and interrupted-reorganization recovery.
Targeted Rust formatting and `git diff --check` also passed. This was a focused
follow-up, not another full-workspace run. Log:
`/tmp/kryptos-consensus-revision-one.log`.

## Tail fee-offset follow-up

The tail fee-offset policy was implemented after the validation history above.
At heights greater than 525,600, new issuance is the scheduled 0.25-coin tail
ceiling minus all included declared fees, clamped to zero. The coinbase receives
that issuance plus the entire fee total. Initial issuance remains unchanged,
and each tail block computes its own offset. `getmininginfo.subsidy` reports the
selected template's actual issuance; the blockchain-info tail field remains
the scheduled ceiling. Revision stays `1`, while a policy tag makes the rules
digest distinguish the former additive payout formula.

Focused checks passed **198 tests, with no failures**:

- Protocol library: 137 tests, including tail thresholds, the last initial and
  first tail heights, aggregate fees, per-block reset and overflow boundaries.
- Chain library: 50 tests, including the policy's rules-digest binding while
  keeping revision 1 and the existing storage/reorganization checks.
- Selected chain integration: the tail-offset regression and the existing
  initial-phase fee-payment regression passed (2 tests).
- Selected mempool integration: an above-minimum declared fee was accepted,
  selected and paid to the miner in the initial phase (1 test).
- Runtime miner unit tests: 6 tests, including template issuance and coinbase
  payout for zero, below-tail, equal-tail, above-tail and multiple fees.
- Mining/RPC integration: 2 tests, using temporary nodes and local listeners.

The tail authorization regression uses real transfer/coinbase proofs and
signatures and rejects the former excessive additive payout. Its synthetic
high-height headers select reward rules only for stateless authorization; it
does not claim a full 525,601-block import or ancestry test. Runtime tail
accounting fixtures likewise do not assemble synthetic ancestry.

Targeted Rust formatting, `git diff --check` and the Tor-only source guard
passed. Runtime checks used the permitted local-listener environment outside
the restricted sandbox, without enabling public-Tor tests. This was a focused
recheck, not another full-workspace run. Local logs:
`/tmp/kryptos-tail-offset-protocol.log`,
`/tmp/kryptos-tail-offset-chain-lib.log`, and
`/tmp/kryptos-tail-offset-runtime.log`.

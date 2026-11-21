//! Block validation.
//!
//! [`Validator::validate_and_apply`] is the stateful path, in order,
//! cheapest first: header shape, timestamps, target, proof of work,
//! transaction root, per-transaction structure and anchors, nullifier
//! freshness, then one batch of signatures and one batch of proofs, and
//! finally the commitment root after appending every new coin.
//!
//! [`Validator::check_authorization`] is the stateless subset: transaction
//! count, structure, balances, signatures and proofs. Side-chain blocks
//! pass it before they are stored. The txid and the transaction root
//! exclude proofs and signatures, so without this check a peer could
//! store an unverifiable body under a valid header hash and the node would
//! then refuse the real body as already known.

use std::collections::BTreeSet;

use crypto::signature::BatchVerifier;
use protocol::amount::RawCoin;
use protocol::block::{Block, BlockHeader};
use protocol::consensus::{next_height, BranchId, BLOCK_VERSION, MAX_BLOCK_TRANSACTIONS};
use protocol::fee::block_mint;
use protocol::nullifier::Nullifier;
use protocol::transaction::Transaction;
use protocol::tree_order::tree_transactions;
use protocol::validate as tx_validate;
use rand_core::{CryptoRng, RngCore};
use storage::store::{BlockStateViolation, Store};
use storage::tree::CommitmentTree;
use transaction_proof::{ProofBatch, VerifyingKey};

use crate::difficulty::{next_target, Sample};
use crate::params::ChainParams;
use crate::pow::RandomXPow;
use crate::target::{ChainWork, Target};
use crate::{Error, Result};

/// Headers whose timestamps form the median a new block must exceed.
pub const MEDIAN_TIME_SPAN: usize = 11;

/// How many headers before a block the header rules look at: the
/// difficulty rule needs `difficulty_window + 1` to form its solve-time
/// pairs, the timestamp rule [`MEDIAN_TIME_SPAN`]. Validation and block
/// templates must use the same count or a miner disagrees with its own
/// validator once the chain is long enough to retarget.
pub fn header_lookback(params: &ChainParams) -> usize {
    params
        .difficulty_window
        .saturating_add(1)
        .max(MEDIAN_TIME_SPAN)
}

/// Keep the anchors needed immediately after the deepest permitted rollback.
pub(crate) fn frontier_retention(params: &ChainParams) -> u32 {
    params.max_reorg_depth.saturating_add(params.anchor_max_age)
}

/// Header/frontier ranges that must remain available to export configured
/// checkpoint snapshots after the canonical tip advances.
pub(crate) fn pinned_checkpoint_ranges(params: &ChainParams) -> Vec<(u32, u32)> {
    let history =
        frontier_retention(params).max(u32::try_from(header_lookback(params)).unwrap_or(u32::MAX));
    params
        .checkpoints
        .iter()
        .map(|checkpoint| (checkpoint.height.saturating_sub(history), checkpoint.height))
        .collect()
}

/// What the validator needs besides the block.
pub struct Validator<'a> {
    /// Network parameters.
    pub params: &'a ChainParams,
    /// Proof of work for those parameters.
    pub pow: &'a RandomXPow,
    /// The circuit verifying key.
    pub vk: &'a VerifyingKey,
    /// Network identifier used to bind v2 state roots.
    pub chain_id: &'a [u8; 32],
    /// Local wall-clock time in seconds, for the future-timestamp rule.
    pub now: u64,
}

impl Validator<'_> {
    /// Validates `block` against the tip of `store` and, if valid, applies
    /// it. Returns the commitment tree after the block.
    ///
    /// # Errors
    /// Returns the first rule violated, or a storage error.
    pub fn validate_and_apply(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<CommitmentTree> {
        self.validate_and_apply_inner(store, block, rng, false)
    }

    /// Applies a block whose exact authorization bytes were checked by the
    /// chain's private authorization token. State and header checks still run.
    pub(crate) fn validate_authorized_and_apply(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<CommitmentTree> {
        self.validate_and_apply_inner(store, block, rng, true)
    }

    fn validate_and_apply_inner(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
        authorization_checked: bool,
    ) -> Result<CommitmentTree> {
        let tip = store.tip()?.ok_or(Error::InvalidBlock("no genesis"))?;
        let header = block.header();
        if header.prev_hash != tip.hash || header.height != next_height(tip.height)? {
            return Err(Error::InvalidHeader("does not extend the tip"));
        }
        self.check_checkpoint(block)?;
        let recent = recent_headers(store, tip.height, self.window())?;
        let target = self.check_header(header, &recent)?;
        let work = child_chainwork(store, header, target)?;
        self.check_checkpoint_work(header, work)?;
        store.check_header_history(header)?;
        block.check_tx_root()?;
        block.check_body_root()?;

        let tree = self.check_transactions(store, block, rng, authorization_checked)?;
        if tree.root() != header.commitment_root {
            return Err(Error::InvalidHeader("commitment root mismatch"));
        }
        let nullifiers = block
            .transactions()
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect::<Vec<_>>();
        let transition = store.preview_nullifier_transition(header.prev_hash, &nullifiers)?;
        if transition.root() != header.nullifier_root {
            return Err(Error::InvalidHeader("nullifier root mismatch"));
        }
        let expected_state_root = crate::state::state_root(
            self.chain_id,
            header.height,
            tree.root(),
            tree.size(),
            transition.root(),
            transition.count(),
        );
        if expected_state_root != header.state_root {
            return Err(Error::InvalidHeader("state root mismatch"));
        }
        store.apply_with_nullifier_transition(block, &tree, &work.to_be_bytes(), &transition)?;
        let frontier_floor = header
            .height
            .saturating_sub(frontier_retention(self.params));
        store.prune_branch_state(
            self.params.max_reorg_depth,
            frontier_floor,
            &pinned_checkpoint_ranges(self.params),
        )?;
        Ok(tree)
    }

    /// Checks a side-chain block before it is stored: its header against
    /// its own ancestry (height, timestamp, target, proof of work), the
    /// checkpoint at its height, the transaction root, and everything
    /// stateless about its transactions. Nothing here needs the tip.
    ///
    /// # Errors
    /// Returns [`Error::Orphan`] if the parent is unknown, or the first
    /// rule violated.
    pub fn check_side_chain_block(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        self.check_side_chain_block_inner(store, block, rng, false)
    }

    /// Stores a side block after its exact authorization bytes were checked
    /// off-thread. Parent, branch state, roots and all header rules still run.
    pub(crate) fn check_authorized_side_chain_block(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        self.check_side_chain_block_inner(store, block, rng, true)
    }

    fn check_side_chain_block_inner(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
        authorization_checked: bool,
    ) -> Result<()> {
        let header = block.header();
        let parent = store.header(&header.prev_hash)?.ok_or(Error::Orphan)?;
        if header.height != next_height(parent.height)? {
            return Err(Error::InvalidHeader("height does not follow the parent"));
        }
        self.check_checkpoint(block)?;
        let recent = branch_headers(store, &parent, self.window())?;
        let target = self.check_header(header, &recent)?;
        let work = child_chainwork(store, header, target)?;
        self.check_checkpoint_work(header, work)?;
        store.check_header_history(header)?;
        block.check_tx_root()?;
        block.check_body_root()?;
        if authorization_checked {
            // Recheck encoding/structure and branch-dependent statements; only
            // the signature and proof batch verification has been completed.
            self.queue_block(block)?;
        } else {
            self.check_authorization(block, rng)?;
        }
        let mut tree = store
            .commitment_tree_at(&header.prev_hash)?
            .ok_or(Error::InvalidBlock("parent commitment tree missing"))?;
        for tx in tree_transactions(block)? {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        if tree.root() != header.commitment_root {
            return Err(Error::InvalidHeader("commitment root mismatch"));
        }
        let nullifiers = block
            .transactions()
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect::<Vec<_>>();
        let transition = store.preview_nullifier_transition(header.prev_hash, &nullifiers)?;
        if transition.root() != header.nullifier_root {
            return Err(Error::InvalidHeader("nullifier root mismatch"));
        }
        let expected_state_root = crate::state::state_root(
            self.chain_id,
            header.height,
            tree.root(),
            tree.size(),
            transition.root(),
            transition.count(),
        );
        if expected_state_root != header.state_root {
            return Err(Error::InvalidHeader("state root mismatch"));
        }
        store.put_block_with_nullifier_transition(
            block,
            &tree,
            &work.to_be_bytes(),
            &transition,
        )?;
        Ok(())
    }

    /// Headers the timestamp and difficulty rules look back over.
    fn window(&self) -> usize {
        header_lookback(self.params)
    }

    fn check_checkpoint(&self, block: &Block) -> Result<()> {
        if self
            .params
            .checkpoint_at(block.header().height)
            .is_some_and(|c| c.hash != block.hash() || c.state_root != block.header().state_root)
        {
            return Err(Error::InvalidHeader("conflicts with a checkpoint"));
        }
        Ok(())
    }

    fn check_checkpoint_work(&self, header: &BlockHeader, work: ChainWork) -> Result<()> {
        if self
            .params
            .checkpoint_at(header.height)
            .is_some_and(|checkpoint| checkpoint.work != work)
        {
            return Err(Error::InvalidHeader("conflicts with a checkpoint"));
        }
        Ok(())
    }

    /// The header rules that depend only on the headers before it:
    /// version, timestamp, target and proof of work, cheapest first.
    fn check_header(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<Target> {
        let target = self.check_header_rules(header, recent)?;
        self.pow.check(header)?;
        Ok(target)
    }

    /// Checks version, timestamp and exact compact difficulty against ancestry,
    /// returning the validated target from which work may be calculated.
    /// `recent` is the parent's ancestry, oldest first, with at least
    /// [`header_lookback`] entries unless genesis is reached first.
    ///
    /// The caller checks linkage and checkpoints, and either checks `RandomX` or
    /// proves this header is an ancestor of a trusted checkpoint before using
    /// its work for synchronization.
    ///
    /// # Errors
    /// Returns the first violated header rule or invalid historical target.
    pub fn check_header_rules(
        &self,
        header: &BlockHeader,
        recent: &[BlockHeader],
    ) -> Result<Target> {
        if header.version != BLOCK_VERSION {
            return Err(Error::InvalidHeader("unknown version"));
        }
        self.check_timestamp(header, recent)?;
        self.check_target(header, recent)
    }

    fn check_timestamp(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<()> {
        let mut times: Vec<u64> = recent
            .iter()
            .rev()
            .take(MEDIAN_TIME_SPAN)
            .map(|h| h.timestamp)
            .collect();
        times.sort_unstable();
        let median = times.get(times.len() / 2).copied().unwrap_or(0);
        if header.timestamp <= median {
            return Err(Error::InvalidHeader("timestamp not after median"));
        }
        if header.timestamp > self.now.saturating_add(self.params.max_future_seconds) {
            return Err(Error::InvalidHeader("timestamp too far in the future"));
        }
        Ok(())
    }

    fn check_target(&self, header: &BlockHeader, recent: &[BlockHeader]) -> Result<Target> {
        let samples = recent
            .iter()
            .map(|h| {
                Ok(Sample {
                    timestamp: h.timestamp,
                    target: Target::from_compact(h.target)?,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let expected = next_target(self.params, header.height, &samples);
        // Comparing encoded nBits also rejects alternate encodings of an
        // otherwise equal target: headers must carry the canonical DAA output.
        if header.target == expected.to_compact() {
            Ok(expected)
        } else {
            Err(Error::InvalidHeader(
                "target does not match the difficulty rule",
            ))
        }
    }

    /// Checks everything about the transactions that needs no chain
    /// state: count, structure, balances, signatures and proofs.
    ///
    /// # Errors
    /// Returns the first rule violated.
    pub fn check_authorization(
        &self,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<()> {
        self.queue_block(block)?.verify(self.vk, rng)
    }

    /// Checks every transaction and returns the tree after the outputs the
    /// block appends, in block transaction order.
    fn check_transactions(
        &self,
        store: &Store,
        block: &Block,
        rng: &mut (impl RngCore + CryptoRng),
        authorization_checked: bool,
    ) -> Result<CommitmentTree> {
        // Shape bounds allocations and rejects duplicate nullifiers before
        // consulting state. Fees and authorization come after state checks.
        block_shape(block)?;
        let anchors: Vec<_> = block
            .transactions()
            .iter()
            .map(|transaction| *transaction.anchor())
            .collect();
        let nullifiers: Vec<_> = block
            .transactions()
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect();
        match store.check_block_state(&anchors, &nullifiers, self.params.anchor_max_age)? {
            Some(BlockStateViolation::UnknownOrStaleAnchor) => {
                return Err(Error::InvalidBlock("unknown or stale anchor"));
            }
            Some(BlockStateViolation::NullifierAlreadySpent) => {
                return Err(Error::InvalidBlock("nullifier already spent"));
            }
            None => {}
        }
        if !authorization_checked {
            self.queue_block(block)?.verify(self.vk, rng)?;
        } else {
            // A token skips only expensive authorization, not the current
            // shape, state or fee rules.
            block_plan(block)?;
        }
        let mut tree = store.tree()?;
        for tx in tree_transactions(block)? {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        Ok(tree)
    }

    fn queue_block(&self, block: &Block) -> Result<AuthorizationBatch> {
        let (coinbase, transfers, mint) = block_plan(block)?;
        let branch = self.params.branch_at(block.header().height);
        let mut batch = AuthorizationBatch::default();
        batch.queue_coinbase(coinbase, mint, branch)?;
        for tx in transfers {
            batch.queue_transfer(tx, branch)?;
        }
        Ok(batch)
    }
}

/// Adds work only after header validation has produced `target`.
fn child_chainwork(store: &Store, header: &BlockHeader, target: Target) -> Result<ChainWork> {
    let parent = store
        .chainwork(&header.prev_hash)?
        .ok_or(Error::InvalidBlock("parent chain work missing"))?;
    ChainWork::from_be_bytes(parent).checked_add(target.work()?)
}

/// Splits the block and computes the mint the coinbase must carry.
fn block_plan(block: &Block) -> Result<(&Transaction, &[Transaction], RawCoin)> {
    let (coinbase, transfers) = block_shape(block)?;
    coinbase.check_fee()?;
    for tx in transfers {
        tx.check_fee()?;
    }
    let mint = block_mint(
        block.header().height,
        transfers.iter().map(Transaction::fee),
    )?;
    protocol::validate::coinbase_balance(mint)?;
    Ok((coinbase, transfers, mint))
}

/// Checks bounded transaction shapes without fees, signatures or proofs.
fn block_shape(block: &Block) -> Result<(&Transaction, &[Transaction])> {
    let txs = block.transactions();
    if txs.is_empty() || txs.len() > MAX_BLOCK_TRANSACTIONS {
        return Err(Error::InvalidBlock("transaction count out of range"));
    }
    let coinbase = txs.first().ok_or(Error::InvalidBlock("missing coinbase"))?;
    if coinbase.kind() != protocol::consensus::COINBASE_KIND {
        return Err(Error::InvalidBlock("first transaction must be coinbase"));
    }
    if txs
        .iter()
        .skip(1)
        .any(|tx| tx.kind() != protocol::consensus::TRANSFER_KIND)
    {
        return Err(Error::InvalidBlock(
            "only the first transaction may be coinbase",
        ));
    }
    let transfers = &txs[1..];
    if coinbase.actions().len() != 2 {
        return Err(Error::InvalidBlock(
            "coinbase must create exactly two states",
        ));
    }
    tx_validate::check_coinbase_shape(coinbase)?;
    let mut seen = BTreeSet::new();
    for tx in txs {
        if tx.kind() == protocol::consensus::TRANSFER_KIND {
            tx_validate::check_transfer_shape(tx)?;
        }
        for nf in tx.nullifiers() {
            if !seen.insert(*nf) {
                return Err(Error::InvalidBlock("nullifier already spent"));
            }
        }
    }
    Ok((coinbase, transfers))
}

/// One block's signatures and proofs, verified together at the end, and
/// the nullifiers seen so far, so a nullifier spent twice within the
/// block is caught before any expensive verification.
#[derive(Default)]
struct AuthorizationBatch {
    signatures: BatchVerifier,
    proofs: ProofBatch,
    seen: BTreeSet<Nullifier>,
}

impl AuthorizationBatch {
    fn queue_coinbase(&mut self, tx: &Transaction, mint: RawCoin, branch: BranchId) -> Result<()> {
        tx_validate::check_coinbase_structure(tx)?;
        self.queue_nullifiers(tx.nullifiers().copied().collect())?;
        tx_validate::queue_checked_signatures(
            tx,
            tx_validate::coinbase_balance(mint)?,
            branch,
            &mut self.signatures,
        )?;
        tx_validate::queue_coinbase_proof(tx, &mut self.proofs)?;
        Ok(())
    }

    fn queue_transfer(&mut self, tx: &Transaction, branch: BranchId) -> Result<()> {
        tx_validate::check_structure(tx)?;
        self.queue_nullifiers(tx.nullifiers().copied().collect())?;
        tx_validate::queue_transfer(tx, branch, &mut self.signatures, &mut self.proofs)?;
        Ok(())
    }

    fn queue_nullifiers(&mut self, nullifiers: Vec<Nullifier>) -> Result<()> {
        for nf in nullifiers {
            if !self.seen.insert(nf) {
                return Err(Error::InvalidBlock("nullifier already spent"));
            }
        }
        Ok(())
    }

    fn verify(self, vk: &VerifyingKey, rng: &mut (impl RngCore + CryptoRng)) -> Result<()> {
        self.signatures.verify(rng)?;
        self.proofs.verify(vk)?;
        Ok(())
    }
}

/// The last `count` headers ending at `parent`, oldest first, found by
/// following previous-hash links, so it works for any stored branch.
///
/// # Errors
/// Fails on a storage error or a missing ancestor.
pub fn branch_headers(
    store: &Store,
    parent: &BlockHeader,
    count: usize,
) -> Result<Vec<BlockHeader>> {
    let mut headers = vec![parent.clone()];
    while headers.len() < count {
        let Some(last) = headers.last() else { break };
        if last.height == 0 {
            break;
        }
        let ancestor = store
            .header(&last.prev_hash)?
            .ok_or(Error::InvalidBlock("ancestor missing"))?;
        if ancestor.height.checked_add(1) != Some(last.height) {
            return Err(Error::InvalidBlock("ancestor height mismatch"));
        }
        headers.push(ancestor);
    }
    headers.reverse();
    Ok(headers)
}

/// The last `count` headers ending at `tip_height`, oldest first.
///
/// # Errors
/// Fails on a storage error or a gap in the height index.
pub fn recent_headers(store: &Store, tip_height: u32, count: usize) -> Result<Vec<BlockHeader>> {
    let count = u32::try_from(count).unwrap_or(u32::MAX);
    let start = tip_height.saturating_sub(count.saturating_sub(1));
    (start..=tip_height)
        .map(|height| {
            let hash = store
                .hash_at(height)?
                .ok_or(Error::InvalidBlock("height index gap"))?;
            let header = store
                .header(&hash)?
                .ok_or(Error::InvalidBlock("block missing"))?;
            if header.height != height {
                return Err(Error::InvalidBlock("height index mismatch"));
            }
            Ok(header)
        })
        .collect()
}

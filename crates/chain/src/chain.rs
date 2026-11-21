//! The chain: imports blocks onto the best chain, keeping side chains and
//! reorganizing to whichever has the most work, with a stable hash tie-break.

use crypto::hash::{blake2b_short, RULES};
use protocol::block::{Block, BlockHash};
use protocol::bytes::Writer;
use rand_core::{CryptoRng, RngCore};
use std::sync::{Arc, Mutex, MutexGuard};
use storage::store::{SnapshotInstall, SnapshotInstallMode, Store, Tip};
use transaction_proof::VerifyingKey;

use crate::genesis::genesis_with_tree;
use crate::params::ChainParams;
use crate::pow::RandomXPow;
use crate::target::ChainWork;
use crate::validate::{frontier_retention, pinned_checkpoint_ranges, Validator};
use crate::{Error, Result};

/// What importing a block did.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Import {
    /// The block was already stored.
    AlreadyKnown,
    /// The block extended the tip.
    Extended,
    /// The block was stored on a side chain that did not win fork choice.
    SideChain,
    /// The block's chain won fork choice; the tip moved to it.
    Reorganized {
        /// Blocks removed from the old best chain, tip first, so their
        /// transactions can be readmitted to the mempool.
        reverted: Vec<Block>,
        /// Blocks applied from the new best chain.
        applied: u32,
    },
}

/// A completed authorization check for one exact block and consensus profile.
///
/// Only [`Chain::authorize_block`] can construct this token. It certifies the
/// transaction signatures and action proofs, not header rules, chain state,
/// PoW, ancestry or fork choice. Import consumes it and checks its binding
/// before touching chain state.
#[derive(Debug)]
pub struct AuthorizedBlock {
    block_hash: BlockHash,
    body_root: [u8; 32],
    chain_id: [u8; 32],
    rules_digest: [u8; 32],
}

/// A chain over a store.
#[derive(Clone)]
pub struct Chain {
    store: Store,
    /// Serializes complete imports, reorg recovery and snapshot installation
    /// across every clone, beyond individual database transactions.
    write_lock: Arc<Mutex<()>>,
    params: ChainParams,
    pow: RandomXPow,
    vk: Arc<VerifyingKey>,
    chain_id: [u8; 32],
    rules_digest: [u8; 32],
}

impl Chain {
    /// Opens the chain, applying genesis if the store is empty.
    ///
    /// # Errors
    /// Fails on invalid issuance parameters, a storage error, or a store
    /// holding a different genesis.
    pub fn new(store: Store, params: ChainParams, vk: VerifyingKey) -> Result<Self> {
        let (expected, tree) = genesis_with_tree(&params);
        let digest = rules_digest(&params, &vk);
        let snapshot_tip = store.snapshot_base()?;
        let has_rules_digest = match store.rules_digest()? {
            // A populated chain without its validating rules cannot be trusted.
            None if store.tip()?.is_some_and(|tip| tip.height > 0) => {
                return Err(Error::RulesMismatch);
            }
            None => false,
            Some(recorded) if recorded == digest => true,
            Some(_) => return Err(Error::RulesMismatch),
        };
        store.set_chain_id(expected.hash().as_bytes())?;
        if snapshot_tip.is_none() {
            match store.hash_at(0)? {
                None => store.apply(&expected, &tree, &ChainWork::ZERO.to_be_bytes())?,
                Some(hash) if hash == expected.hash() => {}
                Some(_) => return Err(Error::InvalidBlock("store belongs to another network")),
            }
        } else if store.chain_id()? != *expected.hash().as_bytes() {
            return Err(Error::InvalidBlock("snapshot belongs to another network"));
        }
        let tip_height = store
            .tip()?
            .ok_or(Error::InvalidBlock("no genesis"))?
            .height;
        let checkpoint_floor = if let Some(base_hash) = snapshot_tip {
            let base_header = store
                .header(&base_hash)?
                .ok_or(Error::InvalidBlock("snapshot base header missing"))?;
            let base_work = store
                .chainwork(&base_hash)?
                .map(ChainWork::from_be_bytes)
                .ok_or(Error::InvalidBlock("snapshot base work missing"))?;
            if !params
                .checkpoint_at(base_header.height)
                .is_some_and(|checkpoint| checkpoint.matches(&base_header, base_work))
            {
                return Err(Error::InvalidBlock(
                    "snapshot base conflicts with configured checkpoint",
                ));
            }
            base_header.height
        } else {
            0
        };
        for checkpoint in params
            .checkpoints
            .iter()
            .filter(|cp| cp.height >= checkpoint_floor && cp.height <= tip_height)
        {
            let header = store
                .header(&checkpoint.hash)?
                .ok_or(Error::InvalidBlock("configured checkpoint block missing"))?;
            let work = store
                .chainwork(&checkpoint.hash)?
                .map(ChainWork::from_be_bytes)
                .ok_or(Error::InvalidBlock("configured checkpoint work missing"))?;
            if !checkpoint.matches(&header, work) {
                return Err(Error::InvalidBlock("store conflicts with a checkpoint"));
            }
        }
        if !has_rules_digest {
            store.set_rules_digest(&digest)?;
        }
        let chain = Self {
            store,
            write_lock: Arc::new(Mutex::new(())),
            params,
            pow: RandomXPow::new(params.randomx_key)?,
            vk: Arc::new(vk),
            chain_id: *expected.hash().as_bytes(),
            rules_digest: digest,
        };
        if snapshot_tip.is_none() && chain.chainwork(&expected.hash())? != ChainWork::ZERO {
            return Err(Error::InvalidBlock("genesis chain work must be zero"));
        }
        {
            let _write = chain.lock_writes();
            chain.recover_reorg()?;
        }
        // Header-only hot paths do not inspect bodies. Retain the full tip
        // decoding check when opening a database so existing body corruption
        // is surfaced before the node starts serving its chain.
        let tip = chain.tip()?;
        if chain.store.block(&tip.hash)?.is_none() && chain.store.snapshot_base()? != Some(tip.hash)
        {
            return Err(Error::InvalidBlock("tip block missing"));
        }
        chain.tip_chainwork()?;
        Ok(chain)
    }

    /// The store.
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The parameters.
    pub fn params(&self) -> &ChainParams {
        &self.params
    }

    /// The fixed genesis hash used as this network's state-root identifier.
    pub fn chain_id(&self) -> &[u8; 32] {
        &self.chain_id
    }

    /// The proof of work.
    pub fn pow(&self) -> &RandomXPow {
        &self.pow
    }

    /// The circuit verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        self.vk.as_ref()
    }

    /// The current tip.
    ///
    /// # Errors
    /// Fails on a storage error.
    pub fn tip(&self) -> Result<Tip> {
        self.store.tip()?.ok_or(Error::InvalidBlock("no genesis"))
    }

    /// Indexed cumulative work of a validated block. Genesis contributes zero:
    /// its fixed header is a network anchor, not a mined proof of work.
    ///
    /// # Errors
    /// Fails if the block has no work index entry or the database cannot be read.
    pub fn chainwork(&self, hash: &BlockHash) -> Result<ChainWork> {
        self.store
            .chainwork(hash)?
            .map(ChainWork::from_be_bytes)
            .ok_or(Error::InvalidBlock("block chain work missing"))
    }

    /// The current tip's cumulative work.
    ///
    /// # Errors
    /// Fails on a missing tip or work index entry, or a storage read error.
    pub fn tip_chainwork(&self) -> Result<ChainWork> {
        self.chainwork(&self.tip()?.hash)
    }

    /// Installs a snapshot bound to this chain's configured checkpoint and
    /// validating rules, under the same lock used by complete block imports.
    ///
    /// Only an empty or exact genesis-only store can be replaced. Storage
    /// rechecks the payload roots, header links and metadata atomically.
    ///
    /// # Errors
    /// Rejects another network, rules profile or checkpoint, an ineligible
    /// store, or invalid snapshot contents. Propagates recovery/storage errors.
    pub fn install_snapshot(&self, snapshot: &SnapshotInstall) -> Result<()> {
        let _write = self.lock_writes();
        self.recover_reorg()?;
        if snapshot.chain_id != self.chain_id || self.store.chain_id()? != self.chain_id {
            return Err(Error::InvalidBlock("snapshot belongs to another network"));
        }
        if snapshot.rules_digest != self.rules_digest
            || self.store.rules_digest()? != Some(self.rules_digest)
        {
            return Err(Error::RulesMismatch);
        }
        let checkpoint = self
            .params
            .checkpoint_at(snapshot.checkpoint.height)
            .ok_or(Error::InvalidBlock("snapshot has no configured checkpoint"))?;
        let tip = snapshot
            .headers
            .last()
            .ok_or(Error::InvalidBlock("snapshot header suffix empty"))?;
        let work = ChainWork::from_be_bytes(snapshot.checkpoint.work);
        if snapshot.checkpoint.hash != checkpoint.hash
            || snapshot.checkpoint.state_root != checkpoint.state_root
            || !checkpoint.matches(&tip.header, work)
        {
            return Err(Error::InvalidBlock(
                "snapshot base conflicts with configured checkpoint",
            ));
        }
        self.store
            .install_snapshot(snapshot, SnapshotInstallMode::EmptyOnly)?;
        Ok(())
    }

    // A panic can leave a multi-transaction reorg journal unfinished. Retain
    // exclusive access even after poison; callers recover that journal before
    // inspecting or mutating chain state, without reacquiring this mutex.
    fn lock_writes(&self) -> MutexGuard<'_, ()> {
        match self.write_lock.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        }
    }

    /// Checks a downloaded block's complete authorization without reading or
    /// mutating its parent state. Suitable for a bounded background worker.
    ///
    /// The transaction and body roots must match the header. Header validity,
    /// anchors, nullifier freshness and state transitions are checked later by
    /// [`Self::import_authorized`] on the serialized chain-import path.
    ///
    /// # Errors
    /// Returns the first encoding, transaction, signature or proof failure.
    pub fn authorize_block(
        &self,
        block: &Block,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<AuthorizedBlock> {
        if block.header().version != protocol::consensus::BLOCK_VERSION {
            return Err(Error::InvalidHeader("unknown version"));
        }
        block.check_tx_root()?;
        block.check_body_root()?;
        self.validator(now).check_authorization(block, rng)?;
        Ok(AuthorizedBlock {
            block_hash: block.hash(),
            body_root: block.header().body_root,
            chain_id: self.chain_id,
            rules_digest: self.rules_digest,
        })
    }

    /// Imports one exact block after its stateless authorization was checked
    /// by [`Self::authorize_block`]. All header and state rules still run at
    /// import time, including the current parent, roots, PoW and fork choice.
    ///
    /// # Errors
    /// Rejects a token from another block/network/profile or changed body
    /// bytes, then propagates the ordinary import and state-validation errors.
    pub fn import_authorized(
        &self,
        block: &Block,
        authorization: AuthorizedBlock,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Import> {
        let _write = self.lock_writes();
        self.recover_reorg()?;
        if authorization.block_hash != block.hash()
            || authorization.body_root != block.header().body_root
            || authorization.chain_id != self.chain_id
            || authorization.rules_digest != self.rules_digest
        {
            return Err(Error::InvalidBlock(
                "authorization token does not match block or rules",
            ));
        }
        // Txids omit authorization bytes. Recompute the complete body root so
        // changing proof/signature bytes cannot reuse a previously valid token.
        block.check_tx_root()?;
        block.check_body_root()?;
        self.import_inner(block, now, rng, true)
    }

    /// Imports a block: extends the tip, stores a side-chain block, or
    /// reorganizes when its branch wins fork choice.
    ///
    /// # Errors
    /// Returns [`Error::Orphan`] if the parent is unknown, or the first
    /// validation failure. A failed reorganization restores the old chain.
    pub fn import(
        &self,
        block: &Block,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Import> {
        let _write = self.lock_writes();
        self.recover_reorg()?;
        self.import_inner(block, now, rng, false)
    }

    fn import_inner(
        &self,
        block: &Block,
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
        authorization_checked: bool,
    ) -> Result<Import> {
        if self.store.hash_at(block.header().height)? == Some(block.hash()) {
            return Ok(Import::AlreadyKnown);
        }
        let tip = self.tip()?;
        if block.header().prev_hash == tip.hash {
            let validator = self.validator(now);
            if authorization_checked {
                validator.validate_authorized_and_apply(&self.store, block, rng)?;
            } else {
                validator.validate_and_apply(&self.store, block, rng)?;
            }
            return Ok(Import::Extended);
        }
        let (fork_height, branch_hashes) = self.branch_to_main_chain(block, tip)?;
        // Side-chain blocks are stored before their chain state can be
        // checked, so require everything else first: the header against
        // its own ancestry and proof of work, or a peer could fill the
        // disk with cheaply made garbage that has a known parent, and the
        // signatures and proofs, or a peer could store an unverifiable
        // body under the valid header hash and the real body would then
        // be refused as already known.
        let validator = self.validator(now);
        if authorization_checked {
            validator.check_authorized_side_chain_block(&self.store, block, rng)?;
        } else {
            validator.check_side_chain_block(&self.store, block, rng)?;
        }
        // Fork choice is independent of block arrival order: greater
        // cumulative work wins, then the lexicographically larger tip hash.
        // Every indexed value came from a validated target.
        let candidate_hash = block.hash();
        let candidate_work = self.chainwork(&candidate_hash)?;
        let tip_work = self.chainwork(&tip.hash)?;
        if candidate_work < tip_work || (candidate_work == tip_work && candidate_hash <= tip.hash) {
            self.store.prune_branch_state(
                self.params.max_reorg_depth,
                tip.height.saturating_sub(frontier_retention(&self.params)),
                &pinned_checkpoint_ranges(&self.params),
            )?;
            return Ok(Import::SideChain);
        }
        let mut branch = branch_hashes
            .iter()
            .map(|hash| self.store.block(hash)?.ok_or(Error::Orphan))
            .collect::<Result<Vec<_>>>()?;
        branch.push(block.clone());
        let authorized_hash = authorization_checked.then(|| block.hash());
        self.reorganize(fork_height, &branch, now, rng, authorized_hash)
    }

    fn validator(&self, now: u64) -> Validator<'_> {
        Validator {
            params: &self.params,
            pow: &self.pow,
            vk: &self.vk,
            chain_id: &self.chain_id,
            now,
        }
    }

    /// Find the eligible fork using only headers, before validating or writing
    /// the incoming side block. Stored heights must strictly decrease, and the
    /// walk stops at the oldest permissible fork. Retain hashes, not bodies;
    /// only a branch that wins on work needs its transactions loaded.
    fn branch_to_main_chain(&self, block: &Block, tip: Tip) -> Result<(u32, Vec<BlockHash>)> {
        let snapshot_floor = self
            .store
            .snapshot_base()?
            .and_then(|hash| self.store.header(&hash).ok().flatten())
            .map_or(0, |header| header.height);
        let checkpoint_floor = self
            .params
            .last_checkpoint_height()
            .max(snapshot_floor)
            .min(tip.height);
        let depth_floor = tip.height.saturating_sub(self.params.max_reorg_depth);
        let mut ancestors = Vec::new();
        let mut header = block.header().clone();
        loop {
            let parent = self.store.header(&header.prev_hash)?.ok_or(Error::Orphan)?;
            if parent.height.checked_add(1) != Some(header.height) {
                return Err(Error::InvalidHeader("height does not follow the parent"));
            }
            if parent.height < checkpoint_floor {
                return Err(Error::InvalidBlock("reorganization below a checkpoint"));
            }
            if parent.height < depth_floor {
                return Err(Error::InvalidBlock("reorganization too deep"));
            }
            if self.store.hash_at(parent.height)? == Some(header.prev_hash) {
                ancestors.reverse();
                return Ok((parent.height, ancestors));
            }
            ancestors.push(header.prev_hash);
            header = parent;
        }
    }

    /// Rolls an interrupted reorg back to its original, previously validated chain.
    /// Each step is durable and repeatable if recovery itself is interrupted.
    fn recover_reorg(&self) -> Result<()> {
        let Some((original, fork)) = self.store.pending_reorg()? else {
            return Ok(());
        };
        let fork_header = self
            .store
            .header(&fork)?
            .ok_or(Error::InvalidBlock("reorg fork header missing"))?;
        let fork_height = fork_header.height;
        let mut old = Vec::new();
        let mut hash = original;
        while hash != fork {
            let block = self
                .store
                .block(&hash)?
                .ok_or(Error::InvalidBlock("reorg original block missing"))?;
            hash = block.header().prev_hash;
            old.push(block);
        }
        while self.tip()?.height > fork_height {
            self.store.revert()?;
        }
        if self.tip()?.hash != fork {
            return Err(Error::InvalidBlock("reorg fork mismatch"));
        }
        let mut tree = self.store.tree()?;
        for block in old.iter().rev() {
            for tx in protocol::tree_order::tree_transactions(block)? {
                for action in tx.actions() {
                    tree.append(action.body().cmx())?;
                }
            }
            let header = block.header();
            if tree.root() != header.commitment_root {
                return Err(Error::InvalidBlock("recovery commitment root mismatch"));
            }
            let nullifiers = block
                .transactions()
                .iter()
                .flat_map(protocol::transaction::Transaction::nullifiers)
                .copied()
                .collect::<Vec<_>>();
            let transition = self
                .store
                .preview_nullifier_transition(header.prev_hash, &nullifiers)?;
            if transition.root() != header.nullifier_root
                || crate::state::state_root(
                    &self.chain_id,
                    header.height,
                    tree.root(),
                    tree.size(),
                    transition.root(),
                    transition.count(),
                ) != header.state_root
            {
                return Err(Error::InvalidBlock("recovery state root mismatch"));
            }
            self.store.apply_with_nullifier_transition(
                block,
                &tree,
                &self.chainwork(&block.hash())?.to_be_bytes(),
                &transition,
            )?;
        }
        self.store.finish_reorg()?;
        let tip_height = self.tip()?.height;
        self.store.prune_branch_state(
            self.params.max_reorg_depth,
            tip_height.saturating_sub(frontier_retention(&self.params)),
            &pinned_checkpoint_ranges(&self.params),
        )?;
        Ok(())
    }

    /// Reverts to `fork_height`, applies `branch`, and restores the old
    /// chain if any branch block is invalid.
    fn reorganize(
        &self,
        fork_height: u32,
        branch: &[Block],
        now: u64,
        rng: &mut (impl RngCore + CryptoRng),
        authorized_hash: Option<BlockHash>,
    ) -> Result<Import> {
        let fork = self.store.hash_at(fork_height)?.ok_or(Error::Orphan)?;
        self.store.begin_reorg(self.tip()?.hash, fork)?;
        let mut reverted = Vec::new();
        while self.tip()?.height > fork_height {
            reverted.push(self.store.revert()?);
        }
        let validator = self.validator(now);
        let mut applied = 0u32;
        for block in branch {
            let checked = if authorized_hash == Some(block.hash()) {
                validator.validate_authorized_and_apply(&self.store, block, rng)
            } else {
                validator.validate_and_apply(&self.store, block, rng)
            };
            if let Err(error) = checked {
                self.recover_reorg()?;
                return Err(error);
            }
            applied = applied.saturating_add(1);
        }
        self.store.finish_reorg()?;
        let tip_height = self.tip()?.height;
        self.store.prune_branch_state(
            self.params.max_reorg_depth,
            tip_height.saturating_sub(frontier_retention(&self.params)),
            &pinned_checkpoint_ranges(&self.params),
        )?;
        Ok(Import::Reorganized { reverted, applied })
    }
}

/// Consensus rules revision, kept at version 1 for the current chain profile.
pub const CONSENSUS_REVISION: u32 = 1;

/// Digest of block validity and fork-choice rules:
/// [`CONSENSUS_REVISION`], every consensus parameter, the genesis branch,
/// the upgrade schedule, the checkpoints and the verifying key.
pub fn rules_digest(params: &ChainParams, vk: &VerifyingKey) -> [u8; 32] {
    rules_digest_for_revision(params, vk, CONSENSUS_REVISION)
}

fn rules_digest_for_revision(params: &ChainParams, vk: &VerifyingKey, revision: u32) -> [u8; 32] {
    rules_digest_with_tail_fee_offset(params, vk, revision, true)
}

fn rules_digest_with_tail_fee_offset(
    params: &ChainParams,
    vk: &VerifyingKey,
    revision: u32,
    tail_fee_offset: bool,
) -> [u8; 32] {
    let mut w = Writer::default();
    w.put(&revision.to_le_bytes());
    w.put(b"kryptos-header-v1-state-roots-tx-merkle-body-merkle-parent-header-mmr");
    w.put(&[protocol::body_tree::BODY_TREE_VERSION]);
    w.put(&[protocol::header_tree::HEADER_TREE_COMMITMENT_VERSION]);
    w.put(&protocol::state::STATE_COMMITMENT_VERSION.to_le_bytes());
    w.put(
        &u64::try_from(protocol::body_tree::BODY_CHUNK_SIZE)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    w.put(
        &u32::try_from(protocol::header_tree::HEADER_TREE_DEPTH)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    w.put(&protocol::consensus::TX_VERSION.to_le_bytes());
    w.put(&[
        protocol::consensus::TRANSFER_KIND,
        protocol::consensus::COINBASE_KIND,
    ]);
    w.put(&[protocol::consensus::BLOCK_VERSION]);
    w.put(&[protocol::encryption::ENCRYPTED_COIN_VERSION]);
    w.put(protocol::transaction::ACTION_PROOF_MAGIC);
    w.put(&protocol::amount::DECIMAL.to_le_bytes());
    w.put(&protocol::amount::RAWCOIN.to_le_bytes());
    w.put(&protocol::consensus::INITIAL_EMISSION.to_le_bytes());
    w.put(&protocol::consensus::TAIL_EMISSION.to_le_bytes());
    w.put(&protocol::consensus::TAIL_HEIGHT.to_le_bytes());
    w.put(&protocol::consensus::TARGET_MINED.to_le_bytes());
    // Bind the payout formula as well as its numeric parameters. The public
    // revision remains 1, but additive-tail history is a different profile.
    if tail_fee_offset {
        w.put(b"kryptos-tail-fee-offset");
    }
    w.put(
        &u64::try_from(params.randomx_key.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    w.put(params.randomx_key);
    w.put(&params.pow_limit.to_compact().to_le_bytes());
    // Only written when set, so a network that never changed its limit
    // keeps the digest its stores were stamped with.
    if let Some(change) = params.pow_limit_change {
        w.put(&change.height.to_le_bytes());
        w.put(&change.limit.to_compact().to_le_bytes());
    }
    w.put(&params.block_interval.to_le_bytes());
    w.put(
        &u64::try_from(params.difficulty_window)
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    w.put(&params.genesis_timestamp.to_le_bytes());
    w.put(&params.anchor_max_age.to_le_bytes());
    w.put(&params.max_future_seconds.to_le_bytes());
    w.put(&params.max_reorg_depth.to_le_bytes());
    w.put(&params.genesis_branch.to_bytes());
    for upgrade in params.upgrades {
        w.put(&upgrade.height.to_le_bytes());
        w.put(&upgrade.branch.to_bytes());
    }
    for checkpoint in params.checkpoints {
        w.put(&checkpoint.height.to_le_bytes());
        w.put(checkpoint.hash.as_bytes());
        w.put(&checkpoint.work.to_be_bytes());
        w.put(&checkpoint.state_root.to_bytes());
    }
    blake2b_short(
        RULES,
        &[&w.into_bytes(), vk.pinned_description().as_bytes()],
    )
}

/// Hash of the block at `height` on the main chain, for tests and tools.
///
/// # Errors
/// Fails on a storage error.
pub fn hash_at(chain: &Chain, height: u32) -> Result<Option<BlockHash>> {
    Ok(chain.store.hash_at(height)?)
}

#[cfg(test)]
mod tests {
    fn empty_state_block(chain: &Chain, parent: BlockHash, height: u32) -> Block {
        let tree = chain.store.commitment_tree_at(&parent).unwrap().unwrap();
        let transition = chain
            .store
            .preview_nullifier_transition(parent, &[])
            .unwrap();
        let mut header = protocol::block::empty_header(height, parent, tree.root());
        header.history_root = chain
            .store
            .header_frontier(&parent)
            .unwrap()
            .unwrap()
            .root();
        header.nullifier_root = transition.root();
        header.state_root = crate::state::state_root(
            chain.chain_id(),
            height,
            tree.root(),
            tree.size(),
            transition.root(),
            transition.count(),
        );
        Block::new(header, Vec::new())
    }

    #[test]
    fn reopening_recovers_every_interrupted_reorg_phase() {
        // Model durable boundaries without proof generation: these empty blocks
        // represent previously validated store state, not network imports.
        for phase in 0..4 {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("chain.redb");
            let params = ChainParams::test();
            let chain = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            let fork = chain.tip().unwrap().hash;
            let tree = chain.store.tree().unwrap();
            let first = empty_state_block(&chain, fork, 1);
            chain.store.apply(&first, &tree, &[1; 32]).unwrap();
            let second = empty_state_block(&chain, first.hash(), 2);
            chain.store.apply(&second, &tree, &[2; 32]).unwrap();
            chain.store.begin_reorg(second.hash(), fork).unwrap();
            if phase >= 1 {
                chain.store.revert().unwrap();
            }
            if phase >= 2 {
                chain.store.revert().unwrap();
            }
            if phase >= 3 {
                let mut header = first.header().clone();
                header.timestamp += 1;
                chain
                    .store
                    .apply(&Block::new(header, vec![]), &tree, &[3; 32])
                    .unwrap();
            }
            chain.store.prune_frontiers_below(100).unwrap();
            assert!(chain.store.tree_at(0).unwrap().is_some());
            drop(chain);
            let recovered = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            assert_eq!(recovered.tip().unwrap().hash, second.hash());
            assert_eq!(recovered.store.hash_at(1).unwrap(), Some(first.hash()));
            assert_eq!(recovered.store.tree().unwrap().root(), tree.root());
            assert_eq!(
                recovered.store.nullifier_root().unwrap(),
                second.header().nullifier_root
            );
            assert_eq!(
                recovered.store.nullifier_count_at(&second.hash()).unwrap(),
                Some(0)
            );
            assert_eq!(
                recovered.store.commitment_count_at(&second.hash()).unwrap(),
                Some(tree.size())
            );
            assert!(recovered.store.pending_reorg().unwrap().is_none());
            drop(recovered);
            let again = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            assert_eq!(again.tip().unwrap().hash, second.hash());
        }
    }

    use protocol::consensus::BranchId;

    use super::*;
    use crate::params::Upgrade;

    static ONE_UPGRADE: [Upgrade; 1] = [Upgrade {
        height: 7,
        branch: BranchId::new(3),
    }];

    #[test]
    fn side_branch_admission_accepts_depth_fifty_and_refuses_fifty_one_without_writing() {
        use rand::SeedableRng;
        // Synthetic storage isolates admission policy; this does not represent
        // proof-of-work or transaction validation for fifty mined blocks.
        let dir = tempfile::tempdir().unwrap();
        let chain = Chain::new(
            Store::open(dir.path().join("chain.redb")).unwrap(),
            ChainParams::test(),
            VerifyingKey::build().unwrap(),
        )
        .unwrap();
        assert_eq!(chain.params.max_reorg_depth, 50);
        let tree = chain.store.tree().unwrap();
        let mut prev = chain.tip().unwrap().hash;
        for height in 1..=52 {
            let block = empty_state_block(&chain, prev, height);
            chain.store.apply(&block, &tree, &[0; 32]).unwrap();
            prev = block.hash();
        }
        let tip = chain.tip().unwrap();
        let fork_at_two = chain.store.hash_at(2).unwrap().unwrap();
        let mut header = protocol::block::empty_header(3, fork_at_two, tree.root());
        header.timestamp = 1;
        let boundary = Block::new(header, vec![]);
        assert_eq!(
            chain.branch_to_main_chain(&boundary, tip).unwrap(),
            (2, vec![])
        );

        let fork_at_one = chain.store.hash_at(1).unwrap().unwrap();
        let mut header = protocol::block::empty_header(2, fork_at_one, tree.root());
        header.timestamp = 1;
        let too_deep = Block::new(header, vec![]);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(51);
        assert!(matches!(
            chain.import(&too_deep, 1, &mut rng),
            Err(Error::InvalidBlock("reorganization too deep"))
        ));
        assert!(!chain.store.contains_block(&too_deep.hash()).unwrap());
        assert_eq!(chain.store.chainwork(&too_deep.hash()).unwrap(), None);
        assert_eq!(chain.tip().unwrap(), tip);
    }

    #[test]
    fn side_branch_below_checkpoint_is_refused_before_persistence() {
        use rand::SeedableRng;
        let dir = tempfile::tempdir().unwrap();
        let mut chain = Chain::new(
            Store::open(dir.path().join("chain.redb")).unwrap(),
            ChainParams::test(),
            VerifyingKey::build().unwrap(),
        )
        .unwrap();
        let tree = chain.store.tree().unwrap();
        let genesis = chain.tip().unwrap().hash;
        let first = empty_state_block(&chain, genesis, 1);
        chain.store.apply(&first, &tree, &[0; 32]).unwrap();
        chain.params.checkpoints = Box::leak(Box::new([crate::params::Checkpoint {
            height: 1,
            hash: first.hash(),
            work: ChainWork::ZERO,
            state_root: first.header().state_root,
        }]));
        let mut header = first.header().clone();
        header.timestamp = 1;
        let side = Block::new(header, vec![]);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(52);
        assert!(matches!(
            chain.import(&side, 1, &mut rng),
            Err(Error::InvalidBlock("reorganization below a checkpoint"))
        ));
        assert!(!chain.store.contains_block(&side.hash()).unwrap());
        assert_eq!(chain.store.chainwork(&side.hash()).unwrap(), None);
        assert_eq!(chain.tip().unwrap().hash, first.hash());
    }

    #[test]
    fn rules_digest_covers_the_branch_and_the_schedule() {
        let vk = VerifyingKey::build().unwrap();
        let base = ChainParams::test();
        assert_eq!(rules_digest(&base, &vk), rules_digest(&base, &vk));
        let scheduled = ChainParams {
            upgrades: &ONE_UPGRADE,
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&scheduled, &vk));
        let other_limit = ChainParams {
            max_reorg_depth: base.max_reorg_depth + 1,
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&other_limit, &vk));
        let mainnet = ChainParams::mainnet();
        let old_spacing = ChainParams {
            block_interval: 300,
            ..mainnet
        };
        assert_eq!(
            genesis_with_tree(&mainnet).0.hash(),
            genesis_with_tree(&old_spacing).0.hash()
        );
        assert_ne!(
            rules_digest(&mainnet, &vk),
            rules_digest(&old_spacing, &vk),
            "the previous mainnet rules require a fresh chain database"
        );
        let other_branch = ChainParams {
            genesis_branch: BranchId::new(4),
            ..base
        };
        assert_ne!(rules_digest(&base, &vk), rules_digest(&other_branch, &vk));
        let eased = ChainParams {
            pow_limit_change: Some(crate::params::PowLimitChange {
                height: 7,
                limit: base.pow_limit,
            }),
            ..base
        };
        let later = ChainParams {
            pow_limit_change: eased
                .pow_limit_change
                .map(|c| crate::params::PowLimitChange { height: 8, ..c }),
            ..base
        };
        assert_ne!(
            rules_digest(&base, &vk),
            rules_digest(&eased, &vk),
            "a store built before a limit change is refused"
        );
        assert_ne!(rules_digest(&eased, &vk), rules_digest(&later, &vk));
        assert_ne!(
            rules_digest(&base, &vk),
            rules_digest(&ChainParams::mainnet(), &vk),
            "networks differ"
        );
    }

    #[test]
    fn rules_digest_binds_tail_fee_offset_while_revision_stays_one() {
        assert_eq!(CONSENSUS_REVISION, 1);
        let params = ChainParams::test();
        let vk = VerifyingKey::build().unwrap();
        assert_eq!(
            rules_digest(&params, &vk),
            rules_digest_with_tail_fee_offset(&params, &vk, 1, true)
        );
        assert_ne!(
            rules_digest(&params, &vk),
            rules_digest_with_tail_fee_offset(&params, &vk, 1, false)
        );
    }

    #[test]
    fn reopening_refuses_different_revisions_without_mutation() {
        assert_eq!(CONSENSUS_REVISION, 1);
        for revision in [2, 3] {
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().join("chain.redb");
            let params = ChainParams::mainnet();
            let chain = Chain::new(
                Store::open(&path).unwrap(),
                params,
                VerifyingKey::build().unwrap(),
            )
            .unwrap();
            let previous_digest =
                rules_digest_for_revision(&params, chain.verifying_key(), revision);
            assert_ne!(previous_digest, chain.rules_digest);

            // Model persisted history without generating proofs: admission must
            // reject the old profile before reading or rewriting its block state.
            let first = empty_state_block(&chain, chain.tip().unwrap().hash, 1);
            let tree = chain.store.tree().unwrap();
            chain.store.apply(&first, &tree, &[0; 32]).unwrap();
            let original_tip = chain.tip().unwrap();
            chain.store.set_rules_digest(&previous_digest).unwrap();
            drop(chain);

            let store = Store::open(&path).unwrap();
            assert!(matches!(
                Chain::new(store.clone(), params, VerifyingKey::build().unwrap()),
                Err(Error::RulesMismatch)
            ));
            assert_eq!(store.rules_digest().unwrap(), Some(previous_digest));
            assert_eq!(store.tip().unwrap(), Some(original_tip));
            assert_eq!(store.block(&first.hash()).unwrap(), Some(first));
        }
    }

    #[test]
    fn reopening_accepts_the_current_revision_one_profile() {
        assert_eq!(CONSENSUS_REVISION, 1);
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("chain.redb");
        let params = ChainParams::test();
        let chain = Chain::new(
            Store::open(&path).unwrap(),
            params,
            VerifyingKey::build().unwrap(),
        )
        .unwrap();
        let expected = rules_digest_for_revision(&params, chain.verifying_key(), 1);
        assert_eq!(rules_digest(&params, chain.verifying_key()), expected);
        assert_eq!(chain.store.rules_digest().unwrap(), Some(expected));
        let original_tip = chain.tip().unwrap();
        drop(chain);

        let reopened = Chain::new(
            Store::open(&path).unwrap(),
            params,
            VerifyingKey::build().unwrap(),
        )
        .unwrap();
        assert_eq!(reopened.store.rules_digest().unwrap(), Some(expected));
        assert_eq!(reopened.tip().unwrap(), original_tip);
    }
}

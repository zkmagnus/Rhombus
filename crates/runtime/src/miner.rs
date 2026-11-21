//! Block templates and the mining task.

use chain::difficulty::{next_target, Sample};
use chain::params::ChainParams;
use chain::pow::RandomXPow;
use chain::target::Target;
use p2p::transport::TorStatus;
use protocol::address::KryptosAddress;
use protocol::amount::RawCoin;
use protocol::block::{empty_header, tx_root, Block, BlockHash, BlockHeader, PowSolution};
use protocol::builder::{Builder, OutputInfo};
use protocol::consensus::{next_height, BLOCK_VERSION};
use protocol::fee::{block_mint, net_issuance, total_fees};
use protocol::header_tree::HeaderFrontier;
use protocol::transaction::Transaction;
use protocol::tree_order::tree_transactions;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use transaction_proof::ProvingKey;

use rand_core::{CryptoRng, RngCore};
use storage::store::Store;
use storage::tree::CommitmentTree;
use tokio::sync::{mpsc, oneshot, watch};
use tokio::task::JoinHandle;

use crate::node::Event;
use crate::{Error, Result};

/// Yield to the node to refresh selected transactions after this many nonces.
const NONCES_PER_BATCH: u32 = 32;
/// Also refresh after this interval, even on slow hashing machines.
const WORK_REFRESH: Duration = Duration::from_secs(5);
/// How long a worker waits before asking again when the node is not
/// ready to mine (Tor unavailable, no peers, or catching up).
const NOT_READY_RETRY: std::time::Duration = std::time::Duration::from_secs(1);

/// What a miner needs to build the next block.
#[derive(Clone, Debug)]
pub struct Template {
    /// The tip header.
    pub parent: BlockHeader,
    /// Recent headers for the difficulty rule, oldest first.
    pub recent: Vec<BlockHeader>,
    /// The tree after the parent.
    pub tree: CommitmentTree,
    /// Authenticated nullifier-state reader for this parent. `None` is only
    /// used by isolated genesis-only fixtures.
    pub nullifier_store: Option<Store>,
    /// Fixed network genesis hash used by the composite state commitment.
    pub chain_id: [u8; 32],
    /// Transactions to include after the coinbase.
    pub transactions: Vec<Transaction>,
    /// Network parameters.
    pub params: ChainParams,
    /// Wall-clock time.
    pub now: u64,
}

impl Template {
    /// Whether an already proved coinbase and block body remain usable.
    /// Time alone changes only the header; every other input must match.
    pub(crate) fn same_work(&self, other: &Self) -> bool {
        self.same_context(other) && self.transactions == other.transactions
    }

    /// Inputs other than timestamp and selected transactions. Pool caches
    /// compare transactions against their shared block body to avoid a copy.
    pub(crate) fn same_context(&self, other: &Self) -> bool {
        self.parent == other.parent
            && self.recent == other.recent
            && self.tree == other.tree
            && self.chain_id == other.chain_id
            && self.params == other.params
    }

    pub(crate) fn timestamp(&self) -> u64 {
        self.now.max(self.parent.timestamp.saturating_add(1))
    }

    /// Builds the coinbase paying `miner` and assembles the header over
    /// it and the template's transactions, with the nonce and solution
    /// still empty. This is the block a pool grinds.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn assemble(
        &self,
        miner: &KryptosAddress,
        pk: &ProvingKey,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<(BlockHeader, Vec<Transaction>)> {
        let height = next_height(self.parent.height)?;
        let mint = self.mint()?;
        let mut coinbase = Builder::new(self.parent.commitment_root);
        coinbase.add_output(OutputInfo::new(miner.clone(), mint))?;
        let coinbase = coinbase.build_coinbase(pk, mint, self.params.branch_at(height), rng)?;

        let mut transactions = vec![coinbase];
        transactions.extend(self.transactions.iter().cloned());
        // The tree after the block, with commitments in transaction order.
        let draft = Block::new(
            empty_header(height, self.parent.hash(), self.parent.commitment_root),
            transactions,
        );
        let mut tree = self.tree.clone();
        let order = tree_transactions(&draft)?;
        for tx in order {
            for action in tx.actions() {
                tree.append(action.body().cmx())?;
            }
        }
        let transactions = draft.transactions().to_vec();
        let nullifiers = transactions
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect::<Vec<_>>();
        let (nullifier_root, nullifier_count) = if let Some(store) = &self.nullifier_store {
            let transition = store.preview_nullifier_transition(self.parent.hash(), &nullifiers)?;
            (transition.root(), transition.count())
        } else {
            let root = storage::nullifier::root_from_set(&self.chain_id, &nullifiers)?;
            (root, u64::try_from(nullifiers.len()).unwrap_or(u64::MAX))
        };
        let state_root = chain::state::state_root(
            &self.chain_id,
            height,
            tree.root(),
            tree.size(),
            nullifier_root,
            nullifier_count,
        );
        let history = if let Some(store) = &self.nullifier_store {
            store
                .header_frontier(&self.parent.hash())?
                .ok_or(chain::Error::InvalidBlock("parent header frontier missing"))?
        } else if self.parent.height == 0 {
            // Isolated genesis fixtures have no storage reader. Later heights
            // must obtain their complete prefix from branch-specific storage.
            let mut history = HeaderFrontier::empty();
            history.append(&self.parent)?;
            history
        } else {
            return Err(chain::Error::InvalidBlock("parent header frontier unavailable").into());
        };
        if history.count() != u64::from(height) || history.tip_hash() != Some(self.parent.hash()) {
            return Err(chain::Error::InvalidBlock("parent header frontier mismatch").into());
        }
        let header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: self.parent.hash(),
            height,
            timestamp: self.timestamp(),
            commitment_root: tree.root(),
            nullifier_root,
            state_root,
            tx_root: tx_root(transactions.iter().map(Transaction::txid)),
            body_root: protocol::body_tree::body_root(&transactions)?,
            history_root: history.root(),
            target: self.next_target()?.to_compact(),
            nonce: [0; 32],
            solution: PowSolution::empty(),
        };
        Ok((header, transactions))
    }

    /// Newly issued value after the selected fees offset the tail subsidy.
    /// Initial-emission blocks retain their full scheduled subsidy.
    ///
    /// # Errors
    /// Fails if the next height or total fee cannot be represented.
    pub fn issuance(&self) -> Result<RawCoin> {
        Ok(net_issuance(
            next_height(self.parent.height)?,
            total_fees(self.transactions.iter().map(Transaction::fee))?,
        )?)
    }

    /// The coinbase payout after fees offset the scheduled tail subsidy.
    /// Initial-emission blocks still pay the subsidy plus all included fees.
    pub fn mint(&self) -> Result<RawCoin> {
        Ok(block_mint(
            next_height(self.parent.height)?,
            self.transactions.iter().map(Transaction::fee),
        )?)
    }

    /// The target the next block must meet.
    ///
    /// # Errors
    /// Fails on a malformed target in the recent headers.
    pub fn next_target(&self) -> Result<Target> {
        let samples = self
            .recent
            .iter()
            .map(|h| {
                Ok(Sample {
                    timestamp: h.timestamp,
                    target: Target::from_compact(h.target)?,
                })
            })
            .collect::<core::result::Result<Vec<_>, chain::Error>>()?;
        Ok(next_target(
            &self.params,
            next_height(self.parent.height)?,
            &samples,
        ))
    }

    /// Assembles the block and mines it, trying a bounded number of
    /// nonces, and giving up early when `keep_going` says no: before the
    /// coinbase proof and before each nonce.
    ///
    /// # Errors
    /// Fails on a building or proving error.
    pub fn mine(
        &self,
        miner: &KryptosAddress,
        pk: &ProvingKey,
        pow: &RandomXPow,
        rng: &mut (impl RngCore + CryptoRng),
        keep_going: impl Fn() -> bool,
    ) -> Result<Option<Block>> {
        if !keep_going() {
            return Ok(None);
        }
        let (mut header, transactions) = self.assemble(miner, pk, rng)?;
        if pow.mine_while(&mut header, NONCES_PER_BATCH, rng, keep_going)? {
            Ok(Some(Block::new(header, transactions)))
        } else {
            Ok(None)
        }
    }
}

/// A proved block body, retained across nonce batches while its inputs match.
struct PreparedWork {
    source: Template,
    header: BlockHeader,
    transactions: Vec<Transaction>,
}

impl PreparedWork {
    fn refresh(&mut self, source: &Template) -> bool {
        if !self.source.same_work(source) {
            return false;
        }
        self.header.timestamp = source.timestamp();
        self.header.solution = PowSolution::empty();
        true
    }

    fn mine_batch(
        &mut self,
        pow: &RandomXPow,
        rng: &mut (impl RngCore + CryptoRng),
        keep_going: impl Fn() -> bool,
    ) -> Result<bool> {
        let started = Instant::now();
        Ok(pow.mine_while(&mut self.header, NONCES_PER_BATCH, rng, || {
            keep_going() && started.elapsed() < WORK_REFRESH
        })?)
    }
}

/// A running miner. Once stopped, workers finish the nonce they are
/// solving (seconds on the main network) and exit. They also drop a
/// template as soon as the best tip moves past its parent, since a block
/// on a stale parent could only become a side-chain block.
pub struct Miner {
    stop: Arc<AtomicBool>,
    task: JoinHandle<Result<()>>,
    /// Where coinbase rewards go.
    pub payout: KryptosAddress,
    /// Worker threads.
    pub threads: usize,
}

impl Miner {
    /// Shared cooperative stop flag for supervisors that also wait for the
    /// worker task to finish before releasing chain storage.
    pub(crate) fn stop_signal(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.stop)
    }

    /// Stops the workers and waits for them.
    ///
    /// # Errors
    /// Returns a failure that stopped a worker before it was asked to.
    pub async fn stop(self) -> Result<()> {
        self.stop.store(true, Ordering::Relaxed);
        self.task.await.map_err(|_| Error::Stopped)?
    }

    /// Waits for the workers without stopping them: until the node loop is
    /// gone, or a worker fails.
    ///
    /// # Errors
    /// Returns the first worker failure.
    pub async fn wait(self) -> Result<()> {
        self.task.await.map_err(|_| Error::Stopped)?
    }
}

/// Starts `threads` workers (at least one) mining to `payout` against the
/// node loop behind `events`. The proving key for the coinbase is built
/// once first, which takes a few seconds. Each worker fetches its own
/// template and mines from a random nonce, so workers explore disjoint
/// nonce ranges with overwhelming probability and their throughput adds up.
pub fn start(
    payout: KryptosAddress,
    params: ChainParams,
    threads: usize,
    events: mpsc::Sender<Event>,
    tip: watch::Receiver<BlockHash>,
) -> Miner {
    start_for_node(payout, params, threads, events, tip, None, None)
}

/// Starts workers that cancel work when transport, peers or sync lose readiness.
/// Offline nodes pass no Tor status.
pub(crate) fn start_for_node(
    payout: KryptosAddress,
    params: ChainParams,
    threads: usize,
    events: mpsc::Sender<Event>,
    tip: watch::Receiver<BlockHash>,
    tor_status: Option<watch::Receiver<TorStatus>>,
    mining_allowed: Option<watch::Receiver<bool>>,
) -> Miner {
    let threads = threads.max(1);
    let stop = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&stop);
    let payout_for_task = payout.clone();
    let task = tokio::spawn(async move {
        let pk = Arc::new(
            tokio::task::spawn_blocking(ProvingKey::build)
                .await
                .map_err(|_| Error::Stopped)??,
        );
        let pow = RandomXPow::new(params.randomx_key)?;
        let mut workers = Vec::with_capacity(threads);
        for _ in 0..threads {
            let worker = Worker {
                payout: payout_for_task.clone(),
                pow: pow.fork()?,
                pk: Arc::clone(&pk),
                stop: Arc::clone(&flag),
                tip: tip.clone(),
                tor_status: tor_status.clone(),
                mining_allowed: mining_allowed.clone(),
            };
            workers.push(tokio::spawn(worker.run(events.clone())));
        }
        for worker in workers {
            worker.await.map_err(|_| Error::Stopped)??;
        }
        Ok(())
    });
    Miner {
        stop,
        task,
        payout,
        threads,
    }
}

/// Whether a worker should try another nonce on a template built on
/// `parent`: it has not been stopped, `parent` is still the best tip, and
/// its embedded Tor service (if any) is ready.
fn worth_mining(
    stop: &AtomicBool,
    tip: &watch::Receiver<BlockHash>,
    parent: BlockHash,
    tor_status: Option<&watch::Receiver<TorStatus>>,
) -> bool {
    !stop.load(Ordering::Relaxed)
        && *tip.borrow() == parent
        && tor_status.is_none_or(crate::tor::service_ready)
}

/// A live node can revoke work for peer loss or sync even when Tor and tip
/// have not changed. Standalone offline workers have no policy watch.
fn policy_allows_mining(allowed: Option<&watch::Receiver<bool>>) -> bool {
    allowed.is_none_or(|ready| ready.has_changed().is_ok() && *ready.borrow())
}

/// What one worker needs.
struct Worker {
    payout: KryptosAddress,
    pow: RandomXPow,
    pk: Arc<ProvingKey>,
    stop: Arc<AtomicBool>,
    tip: watch::Receiver<BlockHash>,
    tor_status: Option<watch::Receiver<TorStatus>>,
    mining_allowed: Option<watch::Receiver<bool>>,
}

impl Worker {
    /// Fetches a template, mines it on the blocking pool, submits any block
    /// found, and repeats until stopped or the node loop is gone.
    async fn run(self, events: mpsc::Sender<Event>) -> Result<()> {
        let mut prepared: Option<PreparedWork> = None;
        while !self.stop.load(Ordering::Relaxed) {
            let (reply, response) = oneshot::channel();
            events
                .send(Event::TemplateRequest(reply))
                .await
                .map_err(|_| Error::Stopped)?;
            let template = match response.await {
                Ok(Ok(template)) => template,
                Ok(Err(_)) => {
                    prepared = None;
                    // The node logs why; mining on its tip now would only
                    // find blocks the network has already moved past.
                    tokio::time::sleep(NOT_READY_RETRY).await;
                    continue;
                }
                Err(_) => return Err(Error::Stopped),
            };
            let (payout, pow, pk) = (self.payout.clone(), self.pow.clone(), Arc::clone(&self.pk));
            let (stop, tip, parent) = (
                Arc::clone(&self.stop),
                self.tip.clone(),
                template.parent.hash(),
            );
            let tor_status = self.tor_status.clone();
            let mining_allowed = self.mining_allowed.clone();
            // Proving and solving are CPU-bound; run them on the blocking pool
            // so many workers use many cores without starving the runtime.
            let (retained, found) = tokio::task::spawn_blocking(move || -> Result<_> {
                let can_mine = || {
                    worth_mining(&stop, &tip, parent, tor_status.as_ref())
                        && policy_allows_mining(mining_allowed.as_ref())
                };
                if !can_mine() {
                    return Ok((None, None));
                }
                let mut rng = rand::rngs::OsRng;
                let mut work = match prepared.filter(|work| work.source.same_work(&template)) {
                    Some(mut work) => {
                        work.refresh(&template);
                        work
                    }
                    None => {
                        let (header, transactions) =
                            template.assemble(&payout, pk.as_ref(), &mut rng)?;
                        PreparedWork {
                            source: template,
                            header,
                            transactions,
                        }
                    }
                };
                // Age from completion of proving so a slow proof does not use
                // the whole nonce budget. Cancellation is checked after proving
                // and before every nonce, including across batch boundaries.
                work.header.timestamp = crate::now().max(work.header.timestamp);
                let found = work.mine_batch(&pow, &mut rng, can_mine)?;
                if !can_mine() {
                    return Ok((None, None));
                }
                if found {
                    Ok((None, Some(Block::new(work.header, work.transactions))))
                } else {
                    Ok((Some(work), None))
                }
            })
            .await
            .map_err(|_| Error::Stopped)??;
            prepared = retained;
            if let Some(block) = found {
                events
                    .send(Event::Mined(Box::new(block)))
                    .await
                    .map_err(|_| Error::Stopped)?;
            }
            tokio::task::yield_now().await;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::arithmetic_side_effects
    )]

    use super::*;
    use rand::SeedableRng;

    fn fixture() -> (Template, KryptosAddress) {
        let params = ChainParams::test();
        let (block, tree) = chain::genesis::genesis_with_tree(&params);
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(972);
        let keys = wallet::keys::WalletKeys::from_spending_key(crypto::keys::SpendingKey::random(
            &mut rng,
        ))
        .unwrap();
        (
            Template {
                parent: block.header().clone(),
                recent: vec![block.header().clone()],
                tree,
                nullifier_store: None,
                chain_id: chain::genesis::genesis(&params)
                    .hash()
                    .as_bytes()
                    .to_owned(),
                transactions: Vec::new(),
                params,
                now: crate::now(),
            },
            keys.default_address().unwrap(),
        )
    }

    /// An encoded transfer for mint arithmetic, not a valid payment.
    fn transfer_with_fee(fee: u64) -> Transaction {
        use crypto::encoding::ENCODED_LEN;
        use protocol::action::{ACTION_BODY_LEN, ACTION_LEN};
        use protocol::bytes::Encodable;
        use protocol::consensus::{TRANSFER_KIND, TX_VERSION};
        use protocol::encryption::ENCRYPTED_COIN_VERSION;
        use protocol::transaction::{ACTION_PROOF_MAGIC, TRANSACTION_HEADER_LEN};

        let actions = 2;
        let mut bytes = vec![0; Transaction::encoded_len_for_actions(actions).unwrap()];
        bytes[0] = TX_VERSION;
        bytes[1] = TRANSFER_KIND;
        bytes[34..42].copy_from_slice(&fee.to_le_bytes());
        bytes[TRANSACTION_HEADER_LEN - 1] = u8::try_from(actions).unwrap();
        for index in 0..actions {
            let encrypted_coin = TRANSACTION_HEADER_LEN + index * ACTION_BODY_LEN + 4 * ENCODED_LEN;
            bytes[encrypted_coin] = ENCRYPTED_COIN_VERSION;
        }
        let proof = TRANSACTION_HEADER_LEN + actions * ACTION_LEN;
        bytes[proof..proof + ACTION_PROOF_MAGIC.len()].copy_from_slice(ACTION_PROOF_MAGIC);
        Transaction::from_slice(&bytes).unwrap()
    }

    #[test]
    fn tail_mint_uses_fees_in_place_of_subsidy_without_double_payment() {
        use protocol::consensus::{TAIL_EMISSION, TAIL_HEIGHT};

        let (mut template, _) = fixture();
        // Only payout accounting is exercised here; no synthetic ancestry is
        // assembled or imported into a chain.
        template.parent.height = u32::try_from(TAIL_HEIGHT).unwrap();
        for (fees, expected_mint, expected_issuance) in [
            (vec![], TAIL_EMISSION, TAIL_EMISSION),
            (vec![TAIL_EMISSION - 1], TAIL_EMISSION, 1),
            (vec![TAIL_EMISSION], TAIL_EMISSION, 0),
            (vec![TAIL_EMISSION + 1], TAIL_EMISSION + 1, 0),
            (
                vec![TAIL_EMISSION / 2, TAIL_EMISSION / 4],
                TAIL_EMISSION,
                TAIL_EMISSION / 4,
            ),
            (vec![TAIL_EMISSION / 2, TAIL_EMISSION / 2], TAIL_EMISSION, 0),
            (
                vec![TAIL_EMISSION / 2, TAIL_EMISSION / 2 + 1],
                TAIL_EMISSION + 1,
                0,
            ),
        ] {
            template.transactions = fees.into_iter().map(transfer_with_fee).collect();
            assert_eq!(template.mint().unwrap().raw(), expected_mint);
            assert_eq!(template.issuance().unwrap().raw(), expected_issuance);
        }
    }

    #[test]
    fn initial_mint_keeps_the_full_subsidy_through_the_last_initial_block() {
        use protocol::consensus::{INITIAL_EMISSION, TAIL_EMISSION, TAIL_HEIGHT};

        let (mut template, _) = fixture();
        template.parent.height = u32::try_from(TAIL_HEIGHT - 1).unwrap();
        for fee in [0, TAIL_EMISSION - 1, TAIL_EMISSION, TAIL_EMISSION + 1] {
            template.transactions = if fee == 0 {
                Vec::new()
            } else {
                vec![transfer_with_fee(fee)]
            };
            assert_eq!(template.mint().unwrap().raw(), INITIAL_EMISSION + fee);
            assert_eq!(template.issuance().unwrap().raw(), INITIAL_EMISSION);
        }
        template.parent.height = u32::try_from(TAIL_HEIGHT).unwrap();
        assert_eq!(template.mint().unwrap().raw(), TAIL_EMISSION + 1);
        assert_eq!(template.issuance().unwrap().raw(), 0);
    }

    #[test]
    fn prepared_work_reuses_proof_but_rejects_changed_inputs_and_cancels() {
        use protocol::bytes::Encodable;
        let (source, payout) = fixture();
        let pk = ProvingKey::build().unwrap();
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(973);
        let started = Instant::now();
        let (header, transactions) = source.assemble(&payout, &pk, &mut rng).unwrap();
        let preparation = started.elapsed();
        let mut work = PreparedWork {
            source: source.clone(),
            header,
            transactions,
        };
        let original = work.transactions.clone();
        let original_root = work.header.tx_root;
        let original_body_root = work.header.body_root;
        let original_history_root = work.header.history_root;
        let mut refreshed = source.clone();
        refreshed.now += 5;
        let started = Instant::now();
        for _ in 0..64 {
            assert!(work.refresh(&refreshed));
        }
        let refresh = started.elapsed();
        eprintln!("mining preparation: {preparation:?}; 64 retained-work refreshes: {refresh:?}");
        assert_eq!(
            work.transactions, original,
            "coinbase proof/body remain identical"
        );
        assert_eq!(work.header.tx_root, original_root);
        assert_eq!(work.header.body_root, original_body_root);
        assert_eq!(work.header.history_root, original_history_root);
        assert_eq!(
            work.header.body_root,
            protocol::body_tree::body_root(&original).unwrap()
        );
        assert_eq!(work.header.timestamp, refreshed.timestamp());

        // Comparing full transactions also catches changed authorization/proof
        // bytes, whose txid is intentionally unchanged by the protocol.
        let mut changed = source.clone();
        changed.transactions = original.clone();
        assert!(
            !work.refresh(&changed),
            "new included transactions require a new body"
        );
        changed = source.clone();
        changed.parent.nonce[0] ^= 1;
        assert!(
            !work.refresh(&changed),
            "same-height parent replacement invalidates work"
        );
        changed = source.clone();
        changed.recent[0].timestamp += 1;
        assert!(!work.refresh(&changed), "difficulty history changed");
        changed = source.clone();
        changed.params.block_interval += 1;
        assert!(!work.refresh(&changed), "network parameters changed");
        changed = source.clone();
        changed
            .tree
            .append(original[0].actions()[0].body().cmx())
            .unwrap();
        assert!(!work.refresh(&changed), "commitment frontier changed");

        let pow = RandomXPow::new(source.params.randomx_key).unwrap();
        let before = work.header.clone();
        assert!(!work.mine_batch(&pow, &mut rng, || false).unwrap());
        assert_eq!(
            work.header, before,
            "cancellation prevents even the first nonce"
        );
        let parent = source.parent.hash();
        let (tip, watched) = watch::channel(parent);
        let stop = AtomicBool::new(false);
        tip.send_replace(BlockHash::from_bytes([99; 32]));
        assert!(!work
            .mine_batch(&pow, &mut rng, || worth_mining(
                &stop, &watched, parent, None
            ))
            .unwrap());
        assert_eq!(work.header, before, "tip movement cancels retained work");
        // Retained work still produces a valid solution after cancellation.
        assert!(work.mine_batch(&pow, &mut rng, || true).unwrap());
        pow.check(&work.header).unwrap();
        assert_eq!(work.transactions, original);

        // On a hard target, unsuccessful batches keep the body and continue
        // sampling fresh random nonces rather than restarting a nonce stream.
        work.header.target = 0x0300_0001;
        assert!(!work.mine_batch(&pow, &mut rng, || true).unwrap());
        let nonce = work.header.nonce;
        assert!(!work.mine_batch(&pow, &mut rng, || true).unwrap());
        assert_ne!(work.header.nonce, nonce);
        assert_eq!(work.transactions, original);

        let mut with_tx = source.clone();
        with_tx.transactions = original.clone();
        let mut altered = with_tx.clone();
        let mut bytes = altered.transactions[0].to_vec();
        *bytes.last_mut().unwrap() ^= 1;
        altered.transactions[0] = Transaction::from_slice(&bytes).unwrap();
        assert_eq!(
            with_tx.transactions[0].txid(),
            altered.transactions[0].txid()
        );
        assert!(
            !with_tx.same_work(&altered),
            "authorization changes invalidate reuse even with the same txid"
        );
    }

    #[test]
    fn work_continues_only_while_unstopped_and_on_the_best_tip() {
        let (a, b) = (
            BlockHash::from_bytes([1; 32]),
            BlockHash::from_bytes([2; 32]),
        );
        let (tip, watched) = watch::channel(a);
        let stop = AtomicBool::new(false);
        assert!(worth_mining(&stop, &watched, a, None));
        assert!(
            !worth_mining(&stop, &watched, b, None),
            "built on a stale parent"
        );
        tip.send_replace(b);
        assert!(!worth_mining(&stop, &watched, a, None), "the tip moved on");
        assert!(worth_mining(&stop, &watched, b, None));
        stop.store(true, Ordering::Relaxed);
        assert!(!worth_mining(&stop, &watched, b, None), "stopped");
    }

    #[test]
    fn active_work_waits_for_tor_and_stops_on_readiness_loss() {
        let parent = BlockHash::from_bytes([1; 32]);
        let (_tip, watched) = watch::channel(parent);
        let stop = AtomicBool::new(false);
        let (status, tor) = watch::channel(TorStatus::default());
        let can_mine = || worth_mining(&stop, &watched, parent, Some(&tor));
        assert!(!can_mine(), "bootstrap must finish before mining");
        let ready = TorStatus {
            client_ready: true,
            onion: Some(p2p::address::NetAddr::TorV3([2; 32])),
        };
        status.send_replace(TorStatus {
            onion: None,
            ..ready
        });
        assert!(!can_mine(), "the onion service must also be ready");
        status.send_replace(TorStatus {
            client_ready: false,
            ..ready
        });
        assert!(!can_mine(), "a service identity alone is insufficient");
        status.send_replace(ready);
        assert!(can_mine());
        status.send_replace(TorStatus::default());
        assert!(!can_mine(), "Tor loss cancels work even on the same tip");
        status.send_replace(ready);
        assert!(can_mine(), "recovery permits work again");
        drop(status);
        assert!(!can_mine(), "a stopped supervisor must block mining");
    }
    #[test]
    fn peer_or_sync_policy_revokes_work_without_a_tip_change() {
        let (policy, watched) = watch::channel(true);
        assert!(policy_allows_mining(Some(&watched)));
        policy.send_replace(false);
        assert!(!policy_allows_mining(Some(&watched)));
        policy.send_replace(true);
        assert!(policy_allows_mining(Some(&watched)));
        drop(policy);
        assert!(!policy_allows_mining(Some(&watched)));
        assert!(policy_allows_mining(None));
    }
}

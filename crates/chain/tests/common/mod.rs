//! Shared mining harness for the chain integration tests.
#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::sync::OnceLock;

use chain::chain::{Chain, Import};
use chain::difficulty::{next_target, Sample};
use chain::params::ChainParams;
use chain::target::Target;
use chain::validate::{header_lookback, recent_headers};
use chain::Error;
use crypto::encryption::TransmissionKey;
use crypto::keys::{Diversifier, FullViewingKey, SpendingKey};
use crypto::merkle::MerkleTree;
use protocol::address::KryptosAddress;
use protocol::amount::RawCoin as Kryptos;
use protocol::block::{empty_header, Block, BlockHeader, PowSolution};
use protocol::builder::{Builder, OutputInfo, SpendInfo};
use protocol::coin::{Coin, Rho};
use protocol::consensus::{BranchId, BLOCK_VERSION};
use protocol::encryption::decrypt_coin_with_ivk;
use protocol::fee::block_mint;
use protocol::transaction::Transaction;
use protocol::tree_order::tree_transactions;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use storage::store::Store;
use storage::tree::CommitmentTree;
use transaction_proof::ProvingKey;

static PK: OnceLock<ProvingKey> = OnceLock::new();

pub fn proving_key() -> &'static ProvingKey {
    PK.get_or_init(|| ProvingKey::build().unwrap())
}

pub struct Wallet {
    pub sk: SpendingKey,
    pub fvk: FullViewingKey,
    pub receiver_key: crypto::encryption::ReceiverKey,
    pub transmission_key: TransmissionKey,
    pub address: KryptosAddress,
    /// Every commitment on the chain, in tree order, for witnesses.
    pub tree: MerkleTree,
    /// Coins this wallet owns, with their tree positions.
    pub coins: Vec<(Coin, u64)>,
}

impl Wallet {
    pub fn new(rng: &mut ChaCha20Rng) -> Self {
        let sk = SpendingKey::random(rng);
        let fvk = FullViewingKey::derive(&sk).unwrap();
        let address = KryptosAddress::derive(&fvk, Diversifier::random(rng)).unwrap();
        let (receiver_key, transmission_key) =
            fvk.receiver_key_for_diversifier(address.diversifier());
        Self {
            sk,
            fvk,
            receiver_key,
            transmission_key,
            address,
            tree: MerkleTree::new(),
            coins: Vec::new(),
        }
    }

    /// Scans the transactions a block appends to the tree, in block order,
    /// the way a wallet would.
    pub fn scan(&mut self, tree: &[&Transaction]) {
        let ivk = self.fvk.incoming_viewing_key().unwrap();
        for tx in tree {
            for action in tx.actions() {
                let body = action.body();
                let position = self.tree.append(*body.cmx().inner()).unwrap();
                let rho = Rho::from_nullifier(body.nullifier()).unwrap();
                if let Ok(coin) = decrypt_coin_with_ivk(
                    &ivk,
                    &self.receiver_key,
                    body.encrypted_coin(),
                    rho,
                    body.cmx(),
                ) {
                    if coin.value().raw() > 0 {
                        self.coins.push((coin, position));
                    }
                }
            }
        }
    }

    /// A copy whose first coin is coin `index`, for spending helpers.
    pub fn clone_for_test(&self, index: usize) -> Self {
        let mut coins = self.coins.clone();
        coins.swap(0, index);
        Self {
            sk: self.sk.clone(),
            fvk: FullViewingKey::derive(&self.sk).unwrap(),
            receiver_key: self
                .fvk
                .receiver_key_for_diversifier(self.address.diversifier())
                .0,
            transmission_key: self.address.kem_key().clone(),
            address: self.address.clone(),
            tree: self.tree.clone(),
            coins,
        }
    }

    pub fn balance(&self) -> u64 {
        self.coins.iter().map(|(n, _)| n.value().raw()).sum()
    }
}

pub struct Harness {
    pub chain: Chain,
    pub rng: ChaCha20Rng,
    pub miner: Wallet,
    /// Seconds between the blocks this harness mines; the network's
    /// block interval unless a test wants faster or slower blocks.
    pub spacing: u64,
    _dir: tempfile::TempDir,
}

impl Harness {
    /// A harness on the test network.
    pub fn new(seed: u64) -> Self {
        Self::with_params(
            seed,
            ChainParams {
                ..ChainParams::test()
            },
        )
    }

    /// A harness on a chain with explicit parameters, for upgrade tests.
    pub fn with_params(seed: u64, params: ChainParams) -> Self {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let dir = tempfile::tempdir().unwrap();
        let chain = Chain::new(
            Store::open(dir.path().join("chain.redb")).unwrap(),
            params,
            proving_key().verifying_key(),
        )
        .unwrap();
        let miner = Wallet::new(&mut rng);
        // Genesis is empty; first coins arrive through mined coinbases.
        Self {
            spacing: params.block_interval,
            chain,
            rng,
            miner,
            _dir: dir,
        }
    }

    /// Builds and mines a block on top of a main-chain `parent`.
    pub fn make_block(&mut self, parent: &BlockHeader, txs: Vec<Transaction>) -> Block {
        let parent_tree = self.chain.store().tree_at(parent.height).unwrap().unwrap();
        self.make_block_on(parent, &parent_tree, txs).0
    }

    /// Builds and mines a block on top of any `parent` whose tree after
    /// application is `parent_tree`. Returns the block and its tree.
    pub fn make_block_on(
        &mut self,
        parent: &BlockHeader,
        parent_tree: &CommitmentTree,
        txs: Vec<Transaction>,
    ) -> (Block, CommitmentTree) {
        self.make_block_after(parent, parent_tree, txs)
    }

    pub fn make_block_after(
        &mut self,
        parent: &BlockHeader,
        parent_tree: &CommitmentTree,
        txs: Vec<Transaction>,
    ) -> (Block, CommitmentTree) {
        let height = parent.height + 1;
        let credit = block_mint(height, txs.iter().map(Transaction::fee)).unwrap();
        let anchor = parent.commitment_root;
        let mut b = Builder::new(anchor);
        b.add_output(OutputInfo::new(self.miner.address.clone(), credit))
            .unwrap();
        let branch = self.chain.params().branch_at(height);
        let coinbase = b
            .build_coinbase(proving_key(), credit, branch, &mut self.rng)
            .unwrap();
        let mut transactions = vec![coinbase];
        transactions.extend(txs);
        let params = *self.chain.params();

        // The tree after this block: the tree at the parent plus the
        // commitments the block appends, in tree order.
        let mut tree = parent_tree.clone();
        let block = Block::new(
            empty_header(height, parent.hash(), parent.commitment_root),
            transactions.clone(),
        );
        for tx in tree_transactions(&block).unwrap() {
            for action in tx.actions() {
                tree.append(action.body().cmx()).unwrap();
            }
        }
        let nullifiers = transactions
            .iter()
            .flat_map(Transaction::nullifiers)
            .copied()
            .collect::<Vec<_>>();
        let nullifier_transition = self
            .chain
            .store()
            .preview_nullifier_transition(parent.hash(), &nullifiers);
        let (nullifier_root, nullifier_count) = match nullifier_transition {
            Ok(transition) => (transition.root(), transition.count()),
            Err(_) => (
                self.chain
                    .store()
                    .nullifier_root_at(&parent.hash())
                    .unwrap()
                    .unwrap(),
                self.chain
                    .store()
                    .nullifier_count_at(&parent.hash())
                    .unwrap()
                    .unwrap(),
            ),
        };
        let state_root = chain::state::state_root(
            self.chain.chain_id(),
            height,
            tree.root(),
            tree.size(),
            nullifier_root,
            nullifier_count,
        );

        let recent =
            recent_headers(self.chain.store(), parent.height, header_lookback(&params)).unwrap();
        let samples: Vec<Sample> = recent
            .iter()
            .map(|h| Sample {
                timestamp: h.timestamp,
                target: Target::from_compact(h.target).unwrap(),
            })
            .collect();
        let mut header = BlockHeader {
            version: BLOCK_VERSION,
            prev_hash: parent.hash(),
            height,
            timestamp: parent.timestamp + self.spacing,
            commitment_root: tree.root(),
            nullifier_root,
            state_root,
            tx_root: protocol::block::tx_root(transactions.iter().map(Transaction::txid)),
            body_root: protocol::body_tree::body_root(&transactions).unwrap(),
            history_root: self
                .chain
                .store()
                .header_frontier(&parent.hash())
                .unwrap()
                .unwrap()
                .root(),
            target: next_target(&params, height, &samples).to_compact(),
            nonce: [0; 32],
            solution: PowSolution::empty(),
        };
        assert!(
            self.chain
                .pow()
                .mine(&mut header, 256, &mut self.rng)
                .unwrap(),
            "mining failed"
        );
        (Block::new(header, transactions), tree)
    }

    pub fn tip_header(&self) -> BlockHeader {
        let tip = self.chain.tip().unwrap();
        self.chain
            .store()
            .block(&tip.hash)
            .unwrap()
            .unwrap()
            .header()
            .clone()
    }

    pub fn import(&mut self, block: &Block) -> Result<Import, Error> {
        let now = block.header().timestamp;
        self.chain.import(block, now, &mut self.rng)
    }

    /// Mines and imports one block on the tip.
    pub fn extend(&mut self, txs: Vec<Transaction>) -> Block {
        let parent = self.tip_header();
        let block = self.make_block(&parent, txs);
        assert_eq!(self.import(&block).unwrap(), Import::Extended);
        self.scan(&block);
        block
    }

    /// Scans a main-chain block into the miner's wallet in tree order.
    pub fn scan(&mut self, block: &Block) {
        let tree = tree_transactions(block).unwrap();
        self.miner.scan(&tree);
    }
}

/// A regular transaction paying `pay` from the wallet's first coin to
/// `recipient`, built against the current tip and signed for the branch
/// of the next block.
pub fn spend_first_coin(
    h: &mut Harness,
    wallet: &Wallet,
    recipient: &KryptosAddress,
    pay: u64,
) -> Transaction {
    let branch = h.chain.params().branch_at(h.tip_header().height + 1);
    spend_first_coin_for(h, wallet, recipient, pay, branch)
}

/// As [`spend_first_coin`], signed for an explicit `branch`.
pub fn spend_first_coin_for(
    h: &mut Harness,
    wallet: &Wallet,
    recipient: &KryptosAddress,
    pay: u64,
    branch: BranchId,
) -> Transaction {
    let (coin, position) = wallet.coins[0].clone();
    let path = wallet.tree.path(position).unwrap();
    let parent = h.tip_header();
    let fee = Transaction::default_fee_for_actions(2).unwrap().raw();
    let change = coin.value().raw() - pay - fee;
    let mut b = Builder::new(parent.commitment_root);
    b.add_spend(SpendInfo::new(wallet.sk.clone(), coin, path))
        .unwrap();
    b.add_output(OutputInfo::new(
        recipient.clone(),
        Kryptos::from_raw(pay).unwrap(),
    ))
    .unwrap();
    if change > 0 {
        b.add_output(OutputInfo::new(
            wallet.address.clone(),
            Kryptos::from_raw(change).unwrap(),
        ))
        .unwrap();
    }
    b.build_with_fee(
        Kryptos::from_raw(fee).unwrap(),
        proving_key(),
        branch,
        &mut h.rng,
    )
    .unwrap()
}

/// A regular transaction with a nonzero public fee.
pub fn spend_first_coin_with_fee(
    h: &mut Harness,
    wallet: &Wallet,
    recipient: &KryptosAddress,
    pay: u64,
    fee: u64,
) -> Transaction {
    let branch = h.chain.params().branch_at(h.tip_header().height + 1);
    let (coin, position) = wallet.coins[0].clone();
    let path = wallet.tree.path(position).unwrap();
    let parent = h.tip_header();
    let change = coin.value().raw() - pay - fee;
    let mut b = Builder::new(parent.commitment_root);
    b.add_spend(SpendInfo::new(wallet.sk.clone(), coin, path))
        .unwrap();
    b.add_output(OutputInfo::new(
        recipient.clone(),
        Kryptos::from_raw(pay).unwrap(),
    ))
    .unwrap();
    if change > 0 {
        b.add_output(OutputInfo::new(
            wallet.address.clone(),
            Kryptos::from_raw(change).unwrap(),
        ))
        .unwrap();
    }
    b.build_with_fee(
        Kryptos::from_raw(fee).unwrap(),
        proving_key(),
        branch,
        &mut h.rng,
    )
    .unwrap()
}

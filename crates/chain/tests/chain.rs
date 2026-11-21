//! End to end: mine blocks with coinbases, spend a coinbase output, reject
//! double spends and bad blocks, and reorganize to a longer side chain.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use chain::chain::{Chain, Import};
use chain::genesis::genesis;
use chain::params::{ChainParams, Upgrade};
use chain::snapshot::{verify_snapshot, SnapshotPayload};
use chain::target::{ChainWork, Target};
use chain::Error;
use common::{proving_key, spend_first_coin_for, spend_first_coin_with_fee, Harness, Wallet};
use protocol::amount::RawCoin;
use protocol::block::{empty_header, Block, PowSolution};
use protocol::builder::{Builder, OutputInfo, SpendInfo};
use protocol::bytes::Encodable;
use protocol::consensus::{subsidy, BranchId, INITIAL_EMISSION, TAIL_EMISSION, TAIL_HEIGHT};
use protocol::transaction::Transaction;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use storage::store::{SnapshotInstallMode, Store};
use storage::tree::CommitmentTree;

/// Exercise the reported mainnet coinbase path with an easy test PoW target.
#[test]
fn mainnet_mined_coinbase_proof_is_accepted() {
    let params = ChainParams {
        pow_limit: ChainParams::test().pow_limit,
        ..ChainParams::mainnet()
    };
    let mut h = Harness::with_params(7306, params);
    let block = h.extend(Vec::new());
    assert_eq!(block.header().height, 1);
    assert_eq!(h.chain.tip().unwrap().height, 1);
    assert_eq!(h.miner.balance(), subsidy(1).raw());
}

#[test]
fn mining_extends_the_chain_and_pays_the_miner() {
    let mut h = Harness::new(1);
    assert_eq!(h.miner.tree.len(), 0, "genesis has no allocated coins");
    let mut work = h.chain.tip_chainwork().unwrap();
    assert_eq!(work, ChainWork::ZERO, "genesis is an unmined anchor");
    for height in 1..=3u32 {
        let block = h.extend(Vec::new());
        assert_eq!(block.header().height, height);
        assert_eq!(h.chain.tip().unwrap().height, height);
        let next = h.chain.tip_chainwork().unwrap();
        assert!(next > work);
        assert_eq!(
            next,
            work.checked_add(
                Target::from_compact(block.header().target)
                    .unwrap()
                    .work()
                    .unwrap()
            )
            .unwrap()
        );
        assert_eq!(
            h.chain.store().chainwork(&block.hash()).unwrap(),
            Some(next.to_be_bytes())
        );
        work = next;
    }
    assert_eq!(h.miner.balance(), 3 * subsidy(1).raw());
    let again = h
        .chain
        .store()
        .block(&h.chain.tip().unwrap().hash)
        .unwrap()
        .unwrap();
    assert_eq!(h.import(&again).unwrap(), Import::AlreadyKnown);
}

#[test]
fn public_fee_is_encoded_and_paid_into_the_coinbase() {
    let mut h = Harness::new(101);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let recipient = Wallet::new(&mut ChaCha20Rng::seed_from_u64(102));
    let fee = protocol::transaction::Transaction::encoded_len_for_actions(2).unwrap() as u64;
    let spending_wallet = h.miner.clone_for_test(0);
    let tx = spend_first_coin_with_fee(&mut h, &spending_wallet, &recipient.address, 1_000, fee);
    assert_eq!(tx.fee().raw(), fee);

    let decoded_tx = Transaction::from_slice(&tx.to_vec()).unwrap();
    assert_eq!(decoded_tx.txid(), tx.txid());
    assert_eq!(decoded_tx.fee(), tx.fee());

    let block = h.make_block(&parent, vec![tx]);
    let decoded_block = Block::from_slice(&block.to_vec()).unwrap();
    assert_eq!(h.import(&decoded_block).unwrap(), Import::Extended);
    h.scan(&decoded_block);

    let reward = protocol::consensus::subsidy(decoded_block.header().height)
        .checked_add(RawCoin::from_raw(fee).unwrap())
        .unwrap();
    assert!(h.miner.coins.iter().any(|(coin, _)| coin.value() == reward));
}

#[test]
fn tail_fees_replace_subsidy_and_reject_legacy_additive_coinbases() {
    let mut h = Harness::new(10_701);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let funded = h.miner.clone_for_test(0);
    let params = *h.chain.params();
    let vk = proving_key().verifying_key();
    let last_initial = u32::try_from(TAIL_HEIGHT).unwrap();
    let first_tail = last_initial + 1;
    let cases = [
        (
            last_initial,
            TAIL_EMISSION / 2,
            INITIAL_EMISSION + TAIL_EMISSION / 2,
        ),
        (first_tail, 0, TAIL_EMISSION),
        (first_tail, TAIL_EMISSION / 2, TAIL_EMISSION),
        (first_tail, TAIL_EMISSION, TAIL_EMISSION),
        (first_tail, TAIL_EMISSION + 1, TAIL_EMISSION + 1),
    ];

    for (height, fee, expected_credit) in cases {
        let branch = params.branch_at(height);
        let fee = RawCoin::from_raw(fee).unwrap();
        let transfers = if fee == RawCoin::ZERO {
            Vec::new()
        } else {
            assert!(fee > Transaction::default_fee_for_actions(2).unwrap());
            let (coin, position) = funded.coins[0].clone();
            let value = coin.value().checked_sub(fee).unwrap();
            let path = funded.tree.path(position).unwrap();
            let mut builder = Builder::new(parent.commitment_root);
            builder
                .add_spend(SpendInfo::new(funded.sk.clone(), coin, path))
                .unwrap();
            builder
                .add_output(OutputInfo::new(funded.address.clone(), value))
                .unwrap();
            vec![builder
                .build_with_fee(fee, proving_key(), branch, &mut h.rng)
                .unwrap()]
        };
        let credit = RawCoin::from_raw(expected_credit).unwrap();
        let mut builder = Builder::new(parent.commitment_root);
        builder
            .add_output(OutputInfo::new(h.miner.address.clone(), credit))
            .unwrap();
        let coinbase = builder
            .build_coinbase(proving_key(), credit, branch, &mut h.rng)
            .unwrap();
        let mut transactions = vec![coinbase];
        transactions.extend(transfers.iter().cloned());

        // The height selects the reward rules for this stateless authorization
        // check. This synthetic header does not claim a mined or imported
        // 525,601-block ancestry, nor does it skip state checks in production.
        let mut header = empty_header(height, parent.hash(), parent.commitment_root);
        header.tx_root = protocol::block::tx_root(transactions.iter().map(Transaction::txid));
        header.body_root = protocol::body_tree::body_root(&transactions).unwrap();
        let block = Block::new(header.clone(), transactions);
        let validator = chain::validate::Validator {
            params: &params,
            pow: h.chain.pow(),
            vk: &vk,
            chain_id: h.chain.chain_id(),
            now: parent.timestamp,
        };
        validator.check_authorization(&block, &mut h.rng).unwrap();

        if height == first_tail && fee != RawCoin::ZERO {
            let additive_credit = subsidy(height).checked_add(fee).unwrap();
            let mut builder = Builder::new(parent.commitment_root);
            builder
                .add_output(OutputInfo::new(h.miner.address.clone(), additive_credit))
                .unwrap();
            let additive_coinbase = builder
                .build_coinbase(proving_key(), additive_credit, branch, &mut h.rng)
                .unwrap();
            // It is a valid proof/signature for the former additive amount;
            // rejection below must come from the validator's expected credit.
            protocol::validate::verify_coinbase(
                &additive_coinbase,
                additive_credit,
                branch,
                &vk,
                &mut h.rng,
            )
            .unwrap();
            let mut transactions = vec![additive_coinbase];
            transactions.extend(transfers);
            header.tx_root = protocol::block::tx_root(transactions.iter().map(Transaction::txid));
            header.body_root = protocol::body_tree::body_root(&transactions).unwrap();
            assert!(matches!(
                validator.check_authorization(&Block::new(header, transactions), &mut h.rng),
                Err(Error::Crypto(crypto::Error::InvalidSignature))
            ));
        }
    }
}

#[test]
fn block_rejects_transfer_below_the_minimum_fee_before_signatures() {
    let mut h = Harness::new(104);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let recipient = Wallet::new(&mut ChaCha20Rng::seed_from_u64(105));
    let fee = protocol::transaction::Transaction::encoded_len_for_actions(2).unwrap() as u64;
    let spending_wallet = h.miner.clone_for_test(0);
    let tx = spend_first_coin_with_fee(&mut h, &spending_wallet, &recipient.address, 1_000, fee);
    let mut bytes = tx.to_vec();
    let fee_offset = 1 + 1 + 32;
    bytes[fee_offset..fee_offset + 8].copy_from_slice(&(fee - 1).to_le_bytes());
    let tampered = Transaction::from_slice(&bytes).unwrap();
    let block = h.make_block(&parent, vec![tampered]);
    assert!(matches!(
        h.import(&block),
        Err(Error::Protocol(protocol::Error::InvalidTransaction(
            "fee is below transaction minimum"
        )))
    ));
}

#[test]
fn a_coinbase_output_can_be_spent_once() {
    let mut h = Harness::new(2);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let (coin, position) = h.miner.coins[0].clone();
    let path = h.miner.tree.path(position).unwrap();
    let parent = h.tip_header();

    let mut rng = ChaCha20Rng::seed_from_u64(99);
    let recipient = Wallet::new(&mut rng);
    let fee = Transaction::default_fee_for_actions(2).unwrap();
    let pay = coin.value().raw() - fee.raw();
    let mut b = Builder::new(parent.commitment_root);
    b.add_spend(SpendInfo::new(h.miner.sk.clone(), coin, path))
        .unwrap();
    b.add_output(OutputInfo::new(
        recipient.address,
        RawCoin::from_raw(pay).unwrap(),
    ))
    .unwrap();
    let tx = b
        .build_with_fee(
            fee,
            proving_key(),
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let nullifier = *tx.actions()[0].body().nullifier();

    let block = h.make_block(&parent, vec![tx.clone()]);
    assert_eq!(h.import(&block).unwrap(), Import::Extended);
    h.scan(&block);
    assert!(
        h.chain.store().contains_nullifier(&nullifier).unwrap()
            || h.chain
                .store()
                .contains_nullifier(tx.actions()[1].body().nullifier())
                .unwrap()
    );

    // The same transaction in the next block is a double spend.
    let parent = h.tip_header();
    let double = h.make_block(&parent, vec![tx]);
    assert!(matches!(
        h.import(&double),
        Err(Error::InvalidBlock("nullifier already spent"))
    ));
}

#[test]
fn bad_blocks_are_rejected() {
    let mut h = Harness::new(3);
    h.extend(Vec::new());
    let parent = h.tip_header();

    let mut orphan = h.make_block(&parent, Vec::new());
    let mut header = orphan.header().clone();
    header.prev_hash = protocol::block::BlockHash::from_bytes([9; 32]);
    orphan = Block::new(header, orphan.transactions().to_vec());
    assert!(matches!(h.import(&orphan), Err(Error::Orphan)));

    let good = h.make_block(&parent, Vec::new());
    let mut wrong_root = good.header().clone();
    wrong_root.commitment_root = parent.commitment_root;
    assert!(h
        .chain
        .pow()
        .mine(&mut wrong_root, 256, &mut h.rng)
        .unwrap());
    let bad = Block::new(wrong_root, good.transactions().to_vec());
    assert!(matches!(
        h.import(&bad),
        Err(Error::InvalidHeader("commitment root mismatch"))
    ));

    let mut bad_nullifier = good.header().clone();
    bad_nullifier.nullifier_root =
        protocol::transaction::Anchor::from_base(crypto::pallas::Base::from(7u64));
    assert!(h
        .chain
        .pow()
        .mine(&mut bad_nullifier, 256, &mut h.rng)
        .unwrap());
    assert!(matches!(
        h.chain.import(
            &Block::new(bad_nullifier, good.transactions().to_vec()),
            good.header().timestamp,
            &mut h.rng,
        ),
        Err(Error::InvalidHeader("nullifier root mismatch"))
    ));

    let mut bad_state = good.header().clone();
    bad_state.state_root =
        protocol::transaction::Anchor::from_base(crypto::pallas::Base::from(8u64));
    assert!(h.chain.pow().mine(&mut bad_state, 256, &mut h.rng).unwrap());
    assert!(matches!(
        h.chain.import(
            &Block::new(bad_state, good.transactions().to_vec()),
            good.header().timestamp,
            &mut h.rng,
        ),
        Err(Error::InvalidHeader("state root mismatch"))
    ));

    let mut no_pow = good.header().clone();
    no_pow.solution = PowSolution::empty();
    assert!(h
        .import(&Block::new(no_pow, good.transactions().to_vec()))
        .is_err());

    let mut future = good.header().clone();
    future.timestamp += 10 * 60 * 60;
    assert!(h.chain.pow().mine(&mut future, 256, &mut h.rng).unwrap());
    let block = Block::new(future, good.transactions().to_vec());
    let now = parent.timestamp;
    assert!(matches!(
        h.chain.import(&block, now, &mut h.rng),
        Err(Error::InvalidHeader("timestamp too far in the future"))
    ));

    assert_eq!(h.import(&good).unwrap(), Import::Extended);
}

#[test]
fn side_chain_blocks_without_proof_of_work_are_not_stored() {
    let mut h = Harness::new(5);
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let mut header = side.header().clone();
    header.solution = PowSolution::empty();
    let unmined = Block::new(header, side.transactions().to_vec());
    assert!(h.import(&unmined).is_err());
    assert!(
        h.chain.store().block(&unmined.hash()).unwrap().is_none(),
        "nothing stored"
    );
}

/// The same block with one byte of its coinbase proof flipped: same txid,
/// same transaction root, same header hash, invalid authorization.
fn with_corrupted_proof(block: &Block) -> Block {
    let tx = &block.transactions()[0];
    let mut bytes = tx.to_vec();
    let proof_offset = 1
        + 32
        + 2
        + 2
        + 32
        + 1
        + tx.actions().len() * protocol::action::ACTION_BODY_LEN
        + tx.actions().len() * crypto::signature::SIGNATURE_LEN;
    // Preserve the proof envelope marker and alter the first action-proof byte.
    bytes[proof_offset + 4] ^= 1;
    let bad = Transaction::from_slice(&bytes).unwrap();
    assert_eq!(bad.txid(), tx.txid(), "the txid excludes the proof");
    let mut txs = block.transactions().to_vec();
    txs[0] = bad;
    Block::new(block.header().clone(), txs)
}

/// Re-mines a sibling with a block hash below `tip_hash`, preserving its
/// transactions and state roots. This lets tests exercise a losing equal-work
/// branch independently of the stable fork-choice tie-break.
fn mine_below_tip(h: &Harness, block: &Block, tip_hash: protocol::block::BlockHash) -> Block {
    let mut header = block.header().clone();
    for nonce in 0u64..1_000_000 {
        header.nonce = [0; 32];
        header.nonce[..8].copy_from_slice(&nonce.to_le_bytes());
        if h.chain.pow().try_nonce(&mut header).unwrap() && header.hash() < tip_hash {
            return Block::new(header, block.transactions().to_vec());
        }
    }
    panic!("could not mine a sibling below the requested tip hash");
}

#[test]
fn a_side_chain_block_with_a_bad_proof_is_not_stored_and_cannot_shadow_the_real_one() {
    let mut h = Harness::new(9);
    h.extend(Vec::new());
    let fork = h.tip_header();
    let main_2 = h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side_2, side_2_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let side_2 = mine_below_tip(&h, &side_2, main_2.hash());
    let poisoned = with_corrupted_proof(&side_2);
    assert_eq!(
        poisoned.hash(),
        side_2.hash(),
        "the header hash is unchanged"
    );

    assert!(h.import(&poisoned).is_err());
    assert!(
        h.chain.store().block(&side_2.hash()).unwrap().is_none(),
        "nothing stored under the valid hash"
    );
    assert_eq!(h.chain.tip().unwrap().hash, main_2.hash());

    // The authentic body is still accepted, and its branch can still win.
    assert_eq!(h.import(&side_2).unwrap(), Import::SideChain);
    let (side_3, _) = h.make_block_on(side_2.header(), &side_2_tree, Vec::new());
    assert!(matches!(
        h.import(&side_3).unwrap(),
        Import::Reorganized { .. }
    ));
    assert_eq!(h.chain.tip().unwrap().hash, side_3.hash());
}

#[test]
fn a_longer_side_chain_triggers_a_reorganization() {
    let mut h = Harness::new(4);
    h.extend(Vec::new());
    let fork = h.tip_header();
    let main_3 = h.extend(Vec::new());
    assert_eq!(h.chain.tip().unwrap().height, 2);

    // A competing branch from the fork point, one block longer. Coinbase
    // randomness makes it differ from the main-chain block at height 2.
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side_2, side_2_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let side_2 = mine_below_tip(&h, &side_2, main_3.hash());
    assert_ne!(side_2.hash(), main_3.hash());
    assert_eq!(h.import(&side_2).unwrap(), Import::SideChain);
    assert_eq!(h.chain.tip().unwrap().hash, main_3.hash());

    let (side_3, _) = h.make_block_on(side_2.header(), &side_2_tree, Vec::new());
    assert_eq!(
        h.import(&side_3).unwrap(),
        Import::Reorganized {
            reverted: vec![main_3.clone()],
            applied: 2
        }
    );
    assert_eq!(h.chain.tip().unwrap().hash, side_3.hash());
    assert_eq!(h.chain.store().hash_at(2).unwrap(), Some(side_2.hash()));
    assert_eq!(h.chain.store().hash_at(3).unwrap(), Some(side_3.hash()));
    assert!(
        h.chain.store().block(&main_3.hash()).unwrap().is_some(),
        "old block kept"
    );
}

#[test]
fn deep_side_branches_are_refused_before_persisting_body_or_work() {
    let mut h = Harness::with_params(
        401,
        ChainParams {
            max_reorg_depth: 2,
            ..ChainParams::test()
        },
    );
    h.extend(Vec::new());
    let fork = h.tip_header();
    let fork_tree = h.chain.store().tree().unwrap();
    let (side, side_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let (unseen_side, _) = h.make_block_on(&fork, &fork_tree, Vec::new());
    h.extend(Vec::new());
    h.extend(Vec::new());
    // Store a lower-work branch at the depth boundary before it ages out.
    assert_eq!(h.import(&side).unwrap(), Import::SideChain);
    let (descendant, _) = h.make_block_on(side.header(), &side_tree, Vec::new());
    h.extend(Vec::new());
    let tip = h.chain.tip().unwrap();
    let work = h.chain.tip_chainwork().unwrap();

    // The stored branch has now aged out; neither its child nor another direct
    // fork from that old canonical parent may leave new persistent entries.
    for rejected in [unseen_side, descendant] {
        assert!(matches!(
            h.import(&rejected),
            Err(Error::InvalidBlock("reorganization too deep"))
        ));
        assert!(!h.chain.store().contains_block(&rejected.hash()).unwrap());
        assert_eq!(h.chain.store().chainwork(&rejected.hash()).unwrap(), None);
        assert_eq!(h.chain.tip().unwrap(), tip);
        assert_eq!(h.chain.tip_chainwork().unwrap(), work);
        assert!(h.chain.store().pending_reorg().unwrap().is_none());
    }
}

#[test]
fn side_branch_can_reorganize_at_the_exact_depth_boundary() {
    let mut h = Harness::with_params(
        402,
        ChainParams {
            max_reorg_depth: 2,
            ..ChainParams::test()
        },
    );
    h.extend(Vec::new());
    let fork = h.tip_header();
    let fork_tree = h.chain.store().tree().unwrap();
    let main_2 = h.extend(Vec::new());
    let main_3 = h.extend(Vec::new());
    let (side_2, tree_2) = h.make_block_on(&fork, &fork_tree, Vec::new());
    assert_eq!(h.import(&side_2).unwrap(), Import::SideChain);
    let (side_3, tree_3) = h.make_block_on(side_2.header(), &tree_2, Vec::new());
    let side_3 = mine_below_tip(&h, &side_3, main_3.hash());
    assert_eq!(h.import(&side_3).unwrap(), Import::SideChain);
    let (side_4, _) = h.make_block_on(side_3.header(), &tree_3, Vec::new());
    assert_eq!(
        h.import(&side_4).unwrap(),
        Import::Reorganized {
            reverted: vec![main_3, main_2],
            applied: 3,
        }
    );
    assert_eq!(h.chain.tip().unwrap().hash, side_4.hash());
    assert_eq!(h.chain.store().hash_at(2).unwrap(), Some(side_2.hash()));
    assert_eq!(h.chain.store().hash_at(3).unwrap(), Some(side_3.hash()));
    assert!(h.chain.store().pending_reorg().unwrap().is_none());
}

#[test]
fn boundary_reorg_retains_anchors_needed_before_the_fork() {
    let mut h = Harness::with_params(
        403,
        ChainParams {
            max_reorg_depth: 1,
            anchor_max_age: 1,
            ..ChainParams::test()
        },
    );
    h.extend(Vec::new());
    let old_anchor = h.tip_header().commitment_root;
    let spender = h.miner.clone_for_test(0);
    let recipient = Wallet::new(&mut ChaCha20Rng::seed_from_u64(404));
    let branch = h.chain.params().branch_at(3);
    let transaction = spend_first_coin_for(&mut h, &spender, &recipient.address, 1_000, branch);
    assert_eq!(transaction.anchor(), &old_anchor);
    h.extend(Vec::new());
    let fork = h.tip_header();
    let fork_tree = h.chain.store().tree().unwrap();
    let main = h.extend(Vec::new());
    assert!(
        h.chain.store().tree_at(1).unwrap().is_some(),
        "fork at height 2 still needs height-1 anchors"
    );
    let (side, side_tree) = h.make_block_on(&fork, &fork_tree, vec![transaction]);
    let side = mine_below_tip(&h, &side, main.hash());
    assert_eq!(h.import(&side).unwrap(), Import::SideChain);
    let (winner, _) = h.make_block_on(side.header(), &side_tree, Vec::new());
    assert_eq!(
        h.import(&winner).unwrap(),
        Import::Reorganized {
            reverted: vec![main],
            applied: 2,
        }
    );
    assert_eq!(h.chain.tip().unwrap().hash, winner.hash());
    assert!(
        h.chain.store().tree_at(1).unwrap().is_none(),
        "the old anchor may be pruned after the new tip no longer needs it"
    );
    assert!(h.chain.store().tree_at(2).unwrap().is_some());
}

#[test]
fn equal_work_fork_choice_is_independent_of_arrival_order() {
    let mut source = Harness::new(41);
    let parent = source.tip_header();
    let a = source.make_block(&parent, Vec::new());
    let b = source.make_block(&parent, Vec::new());
    let (winner, loser) = if a.hash() > b.hash() { (a, b) } else { (b, a) };

    let mut winner_first = Harness::new(42);
    let mut loser_first = Harness::new(43);
    assert_eq!(
        winner_first.chain.tip().unwrap().hash,
        loser_first.chain.tip().unwrap().hash
    );

    assert_eq!(winner_first.import(&winner).unwrap(), Import::Extended);
    assert_eq!(winner_first.import(&loser).unwrap(), Import::SideChain);

    assert_eq!(loser_first.import(&loser).unwrap(), Import::Extended);
    assert_eq!(
        loser_first.import(&winner).unwrap(),
        Import::Reorganized {
            reverted: vec![loser.clone()],
            applied: 1,
        }
    );

    assert_eq!(
        winner_first.chain.chainwork(&winner.hash()).unwrap(),
        winner_first.chain.chainwork(&loser.hash()).unwrap()
    );
    assert_eq!(winner_first.chain.tip().unwrap().hash, winner.hash());
    assert_eq!(loser_first.chain.tip().unwrap().hash, winner.hash());
}

#[test]
fn overflowing_work_does_not_store_the_child_or_move_the_tip() {
    let mut h = Harness::new(42);
    let parent = h.tip_header();
    let child = h.make_block(&parent, Vec::new());
    let genesis = h.chain.store().block(&parent.hash()).unwrap().unwrap();
    // Model a valid indexed ancestry already at the representational limit.
    h.chain
        .store()
        .put_block(&genesis, &ChainWork::MAX.to_be_bytes())
        .unwrap();
    assert!(matches!(h.import(&child), Err(Error::ChainWorkOverflow)));
    assert_eq!(h.chain.tip().unwrap().hash, genesis.hash());
    assert!(h.chain.store().block(&child.hash()).unwrap().is_none());
    assert!(h.chain.store().chainwork(&child.hash()).unwrap().is_none());
}

#[test]
fn equivalent_noncanonical_nbits_are_rejected() {
    let params = ChainParams {
        pow_limit: Target::from_compact(0x207f_ff00).unwrap(),
        checkpoints: &[],
        ..ChainParams::test()
    };
    let h = Harness::with_params(43, params);
    let parent = h.tip_header();
    let mut header = empty_header(1, parent.hash(), parent.commitment_root);
    header.timestamp = parent.timestamp + params.block_interval;
    // Both decode to the same integer; only the DAA's encoding is allowed.
    header.target = 0x2100_7fff;
    assert_eq!(
        Target::from_compact(header.target).unwrap(),
        params.pow_limit
    );
    let chain_id = h.chain.tip().unwrap().hash;
    let validator = chain::validate::Validator {
        params: h.chain.params(),
        pow: h.chain.pow(),
        vk: h.chain.verifying_key(),
        chain_id: chain_id.as_bytes(),
        now: header.timestamp,
    };
    assert!(matches!(
        validator.check_header_rules(&header, &[parent]),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
}

/// One upgrade at height 3 on the test network.
static UPGRADE_AT_3: [Upgrade; 1] = [Upgrade {
    height: 3,
    branch: BranchId::new(0x0000_0002),
}];

/// Configures an upgrade at height 3.
fn params_with_upgrade() -> ChainParams {
    ChainParams {
        upgrades: &UPGRADE_AT_3,
        ..ChainParams::test()
    }
}

#[test]
fn an_upgrade_changes_which_signatures_a_block_accepts() {
    let mut h = Harness::with_params(10, params_with_upgrade());
    let old = h.chain.params().genesis_branch;
    let new = UPGRADE_AT_3[0].branch;
    h.extend(Vec::new());
    h.extend(Vec::new());
    assert_eq!(
        h.chain.tip().unwrap().height,
        2,
        "last block under the old rules"
    );
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(10_000));
    let wallet = h.miner.clone_for_test(0);

    // A transaction signed for the old branch is refused at height 3.
    let parent = h.tip_header();
    let stale = spend_first_coin_for(&mut h, &wallet, &other.address, 1_000, old);
    let coinbase = coinbase_for(&mut h, &parent, old);
    let block = block_over(&mut h, &parent, vec![coinbase, stale]);
    assert!(matches!(
        h.import(&block),
        Err(Error::Crypto(crypto::Error::InvalidSignature))
    ));
    assert_eq!(h.chain.tip().unwrap().height, 2);

    // The same payment signed for the new branch is accepted.
    let fresh = spend_first_coin_for(&mut h, &wallet, &other.address, 1_000, new);
    let block = h.make_block(&parent, vec![fresh]);
    assert_eq!(h.import(&block).unwrap(), Import::Extended);
    assert_eq!(h.chain.params().branch_at(3), new);
}

/// A coinbase for the block after `parent`, signed for `branch`.
fn coinbase_for(
    h: &mut Harness,
    parent: &protocol::block::BlockHeader,
    branch: BranchId,
) -> protocol::transaction::Transaction {
    let credit = subsidy(parent.height + 1);
    let mut b = Builder::new(parent.commitment_root);
    b.add_output(OutputInfo::new(h.miner.address.clone(), credit))
        .unwrap();
    b.build_coinbase(proving_key(), credit, branch, &mut h.rng)
        .unwrap()
}

/// Assembles and mines a block over explicit transactions, computing the
/// tree root itself, so tests can put invalid transaction sets in valid
/// looking blocks.
fn block_over(
    h: &mut Harness,
    parent: &protocol::block::BlockHeader,
    transactions: Vec<protocol::transaction::Transaction>,
) -> Block {
    use chain::difficulty::{next_target, Sample};
    use chain::target::Target;
    use chain::validate::{header_lookback, recent_headers};
    let params = *h.chain.params();
    let mut tree = h
        .chain
        .store()
        .commitment_tree_at(&parent.hash())
        .unwrap()
        .unwrap();
    for tx in &transactions {
        for action in tx.actions() {
            tree.append(action.body().cmx()).unwrap();
        }
    }
    let recent = recent_headers(h.chain.store(), parent.height, header_lookback(&params)).unwrap();
    let samples: Vec<Sample> = recent
        .iter()
        .map(|hd| Sample {
            timestamp: hd.timestamp,
            target: Target::from_compact(hd.target).unwrap(),
        })
        .collect();
    let nullifiers = transactions
        .iter()
        .flat_map(protocol::transaction::Transaction::nullifiers)
        .copied()
        .collect::<Vec<_>>();
    let (nullifier_root, nullifier_count) = match h
        .chain
        .store()
        .preview_nullifier_transition(parent.hash(), &nullifiers)
    {
        Ok(transition) => (transition.root(), transition.count()),
        Err(_) => (
            h.chain
                .store()
                .nullifier_root_at(&parent.hash())
                .unwrap()
                .unwrap(),
            h.chain
                .store()
                .nullifier_count_at(&parent.hash())
                .unwrap()
                .unwrap(),
        ),
    };
    let mut header = protocol::block::BlockHeader {
        version: protocol::consensus::BLOCK_VERSION,
        prev_hash: parent.hash(),
        height: parent.height + 1,
        timestamp: parent.timestamp + params.block_interval,
        commitment_root: tree.root(),
        nullifier_root,
        state_root: chain::state::state_root(
            h.chain.chain_id(),
            parent.height + 1,
            tree.root(),
            tree.size(),
            nullifier_root,
            nullifier_count,
        ),
        tx_root: protocol::block::tx_root(
            transactions
                .iter()
                .map(protocol::transaction::Transaction::txid),
        ),
        body_root: protocol::body_tree::body_root(&transactions).unwrap(),
        history_root: h
            .chain
            .store()
            .header_frontier(&parent.hash())
            .unwrap()
            .unwrap()
            .root(),
        target: next_target(&params, parent.height + 1, &samples).to_compact(),
        nonce: [0; 32],
        solution: PowSolution::empty(),
    };
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, transactions)
}

#[test]
fn a_coinbase_claiming_the_wrong_credit_is_rejected() {
    let mut h = Harness::new(6);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let height = parent.height + 1;
    for wrong in [subsidy(height).raw() + 1, subsidy(height).raw() - 1] {
        let credit = RawCoin::from_raw(wrong).unwrap();
        let mut b = Builder::new(parent.commitment_root);
        b.add_output(OutputInfo::new(h.miner.address.clone(), credit))
            .unwrap();
        let coinbase = b
            .build_coinbase(
                proving_key(),
                credit,
                h.chain.params().branch_at(parent.height + 1),
                &mut h.rng,
            )
            .unwrap();
        let block = block_over(&mut h, &parent, vec![coinbase]);
        assert!(
            matches!(
                h.import(&block),
                Err(Error::Crypto(crypto::Error::InvalidSignature))
            ),
            "{wrong}"
        );
    }
}

#[test]
fn coinbase_with_nonzero_fee_is_rejected_before_binding_verification() {
    let mut h = Harness::new(601);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let credit = subsidy(parent.height + 1);
    let mut builder = Builder::new(parent.commitment_root);
    builder
        .add_output(OutputInfo::new(h.miner.address.clone(), credit))
        .unwrap();
    let coinbase = builder
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let mut encoded = coinbase.to_vec();
    // version + native kind + anchor = offset 34; fee is 8 bytes.
    encoded[36] = 1;
    let malformed = Transaction::from_slice(&encoded).unwrap();
    let block = block_over(&mut h, &parent, vec![malformed]);
    assert!(matches!(
        h.import(&block),
        Err(Error::Protocol(protocol::Error::InvalidTransaction(
            "coinbase fee must be zero",
        )))
    ));
}

#[test]
fn only_the_first_transaction_may_create_value() {
    let mut h = Harness::new(7);
    h.extend(Vec::new());
    let parent = h.tip_header();
    let credit = subsidy(parent.height + 1);
    let mut first = Builder::new(parent.commitment_root);
    first
        .add_output(OutputInfo::new(h.miner.address.clone(), credit))
        .unwrap();
    let coinbase = first
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let mut second = Builder::new(parent.commitment_root);
    second
        .add_output(OutputInfo::new(h.miner.address.clone(), credit))
        .unwrap();
    let extra = second
        .build_coinbase(
            proving_key(),
            credit,
            h.chain.params().branch_at(parent.height + 1),
            &mut h.rng,
        )
        .unwrap();
    let block = block_over(&mut h, &parent, vec![coinbase, extra]);
    assert!(h.import(&block).is_err());
}

#[test]
fn a_failed_apply_leaves_no_partial_state() {
    let mut h = Harness::new(8);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(80));
    // Two transactions spending the same coin: the store's own duplicate
    // check fails mid-transaction, and nothing of the block persists.
    let wallet = h.miner.clone_for_test(0);
    let a = common::spend_first_coin(&mut h, &wallet, &other.address, 1_000);
    let b = common::spend_first_coin(&mut h, &wallet, &other.address, 2_000);
    let parent = h.tip_header();
    let block = block_over(&mut h, &parent, vec![a.clone(), b]);
    let tree = h.chain.store().tree().unwrap();
    let tip_before = h.chain.tip().unwrap();
    assert!(h.chain.store().apply(&block, &tree, &[0; 32]).is_err());
    assert_eq!(h.chain.tip().unwrap(), tip_before);
    assert!(h.chain.store().block(&block.hash()).unwrap().is_none());
    assert!(h.chain.store().chainwork(&block.hash()).unwrap().is_none());
    assert!(!h
        .chain
        .store()
        .contains_nullifier(a.actions()[0].body().nullifier())
        .unwrap());
    assert_eq!(
        h.chain.store().hash_at(tip_before.height + 1).unwrap(),
        None
    );
}

#[test]
fn a_side_chain_block_with_the_wrong_target_is_not_stored() {
    let mut h = Harness::new(11);
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, Vec::new());
    // A target easier than the limit: free to meet, and never what the
    // difficulty rule expects.
    let mut header = side.header().clone();
    let easy = Target::from_compact(0x2100_ffff).unwrap();
    assert!(easy > h.chain.params().pow_limit);
    header.target = easy.to_compact();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    let cheap = Block::new(header, side.transactions().to_vec());
    assert!(matches!(
        h.import(&cheap),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    assert!(h.chain.store().block(&cheap.hash()).unwrap().is_none());
    assert!(h.chain.store().chainwork(&cheap.hash()).unwrap().is_none());
}

#[test]
fn a_side_chain_block_repeating_a_transaction_is_not_stored() {
    let mut h = Harness::new(12);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let fork = h.tip_header();
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(12_000));
    let wallet = h.miner.clone_for_test(0);
    let tx = common::spend_first_coin(&mut h, &wallet, &other.address, 1_000);
    let fork_tree = h.chain.store().tree_at(fork.height).unwrap().unwrap();
    let (side, _) = h.make_block_on(&fork, &fork_tree, vec![tx.clone(), tx]);
    assert!(matches!(
        h.import(&side),
        Err(Error::InvalidBlock("nullifier already spent"))
    ));
    assert!(h.chain.store().block(&side.hash()).unwrap().is_none());
}

#[test]
fn a_store_built_under_other_rules_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("chain.redb");
    let vk = || proving_key().verifying_key();
    drop(Chain::new(Store::open(&path).unwrap(), ChainParams::test(), vk()).unwrap());
    assert!(matches!(
        Chain::new(Store::open(&path).unwrap(), params_with_upgrade(), vk()),
        Err(Error::RulesMismatch)
    ));
    assert!(Chain::new(Store::open(&path).unwrap(), ChainParams::test(), vk()).is_ok());
}

#[test]
fn exported_checkpoint_installs_and_accepts_the_next_block() {
    let mut source = Harness::new(14_001);
    let params = ChainParams::test();
    let checkpoint = source.chain.tip().unwrap();
    let next = source.extend(Vec::new());
    let payload = SnapshotPayload::from_store_at(
        source.chain.store(),
        &params,
        source.chain.chain_id(),
        checkpoint.height,
    )
    .unwrap();
    let rules = chain::chain::rules_digest(&params, source.chain.verifying_key());
    let checkpoint_header = source
        .chain
        .store()
        .header(&checkpoint.hash)
        .unwrap()
        .unwrap();
    verify_snapshot(
        &params,
        &rules,
        source.chain.chain_id(),
        &checkpoint_header,
        ChainWork::ZERO,
        &payload,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let destination_path = dir.path().join("destination.redb");
    let destination = Chain::new(
        Store::open(&destination_path).unwrap(),
        params,
        proving_key().verifying_key(),
    )
    .unwrap();
    destination
        .store()
        .install_snapshot(
            &payload.to_storage_install().unwrap(),
            SnapshotInstallMode::EmptyOnly,
        )
        .unwrap();
    drop(destination);
    let destination = Chain::new(
        Store::open(&destination_path).unwrap(),
        params,
        proving_key().verifying_key(),
    )
    .unwrap();

    assert_eq!(
        destination
            .import(&next, next.header().timestamp, &mut source.rng)
            .unwrap(),
        Import::Extended
    );
    assert_eq!(destination.tip().unwrap(), source.chain.tip().unwrap());
    assert_eq!(
        destination.store().nullifier_root().unwrap(),
        source.chain.store().nullifier_root().unwrap()
    );
    assert_eq!(
        destination.store().tree().unwrap().root(),
        source.chain.store().tree().unwrap().root()
    );
}

/// A block after `parent` declaring the easiest target, mined and
/// otherwise identical to what the harness would build.
fn at_easiest_target(h: &mut Harness, parent: &protocol::block::BlockHeader) -> Block {
    let parent_tree = h.chain.store().tree_at(parent.height).unwrap().unwrap();
    let (block, _) = h.make_block_on(parent, &parent_tree, Vec::new());
    let mut header = block.header().clone();
    header.target = h.chain.params().pow_limit.to_compact();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, block.transactions().to_vec())
}

#[test]
fn a_mainnet_sized_difficulty_window_retargets_and_is_enforced() {
    // A window at least as long as the median span, like mainnet's 60, so
    // the lookback is decided by the difficulty rule and not the median.
    let params = ChainParams {
        difficulty_window: 12,
        ..ChainParams::test()
    };
    let mut h = Harness::with_params(13, params);
    h.spacing = 1;
    // Blocks arrive five times faster than the interval; once the window
    // is full the target drops below the limit and the harness, which
    // computes targets the way the node's miner does, must still be
    // accepted by the validator.
    for _ in 0..14 {
        h.extend(Vec::new());
    }
    let tip = h.tip_header();
    assert!(Target::from_compact(tip.target).unwrap() < params.pow_limit);

    // The easiest target is no longer acceptable, on the main chain...
    let easy = at_easiest_target(&mut h, &tip);
    assert!(matches!(
        h.import(&easy),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    // ...nor on a side chain.
    let fork = h.chain.store().block(&tip.prev_hash).unwrap().unwrap();
    let easy_side = at_easiest_target(&mut h, fork.header());
    assert!(matches!(
        h.import(&easy_side),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    assert!(h.chain.store().block(&easy_side.hash()).unwrap().is_none());
}

/// A block after `parent` declaring `target`, mined and otherwise
/// identical to what the harness would build.
fn at_target(h: &mut Harness, parent: &protocol::block::BlockHeader, target: Target) -> Block {
    let parent_tree = h.chain.store().tree_at(parent.height).unwrap().unwrap();
    let (block, _) = h.make_block_on(parent, &parent_tree, Vec::new());
    let mut header = block.header().clone();
    header.target = target.to_compact();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    Block::new(header, block.transactions().to_vec())
}

#[test]
fn the_pow_limit_changes_at_its_height_and_both_sides_are_enforced() {
    let base = ChainParams::test();
    let new_limit = Target::from_compact(0x203f_ffff).unwrap();
    let params = ChainParams {
        pow_limit_change: Some(chain::params::PowLimitChange {
            height: 3,
            limit: new_limit,
        }),
        ..base
    };
    let mut h = Harness::with_params(15, params);
    h.extend(Vec::new());
    // Below the change the new limit is refused...
    let tip = h.tip_header();
    let early = at_target(&mut h, &tip, new_limit);
    assert!(matches!(
        h.import(&early),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    h.extend(Vec::new());
    assert_eq!(h.tip_header().target, base.pow_limit.to_compact());
    // ...and from it on the old one is.
    let tip = h.tip_header();
    let stale = at_target(&mut h, &tip, base.pow_limit);
    assert!(matches!(
        h.import(&stale),
        Err(Error::InvalidHeader(
            "target does not match the difficulty rule"
        ))
    ));
    for _ in 0..3 {
        h.extend(Vec::new());
        assert_eq!(h.tip_header().target, new_limit.to_compact());
    }
    assert_eq!(h.tip_header().height, 5);
}

#[test]
fn a_store_with_history_but_no_rules_digest_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let vk = || proving_key().verifying_key();
    let params = ChainParams::test();
    let first = genesis(&params);

    // Genesis alone, from a binary that recorded no digest: stamped on open.
    let only_genesis = dir.path().join("genesis.redb");
    Store::open(&only_genesis)
        .unwrap()
        .apply(&first, &CommitmentTree::empty(), &[0; 32])
        .unwrap();
    assert!(Chain::new(Store::open(&only_genesis).unwrap(), params, vk()).is_ok());
    assert!(Store::open(&only_genesis)
        .unwrap()
        .rules_digest()
        .unwrap()
        .is_some());

    // History validated under unknown rules: refused.
    let with_history = dir.path().join("history.redb");
    {
        let store = Store::open(&with_history).unwrap();
        store
            .apply(&first, &CommitmentTree::empty(), &[0; 32])
            .unwrap();
        let mut header = empty_header(1, first.hash(), CommitmentTree::empty().root());
        header.history_root = store
            .header_frontier(&first.hash())
            .unwrap()
            .unwrap()
            .root();
        store
            .apply(
                &Block::new(header, Vec::new()),
                &CommitmentTree::empty(),
                &[0; 32],
            )
            .unwrap();
    }
    assert!(matches!(
        Chain::new(Store::open(&with_history).unwrap(), params, vk()),
        Err(Error::RulesMismatch)
    ));
}

#[test]
fn transactions_are_indexed_by_id_while_in_the_main_chain() {
    let mut h = Harness::new(14);
    h.extend(Vec::new());
    h.extend(Vec::new());
    let other = Wallet::new(&mut ChaCha20Rng::seed_from_u64(14_000));
    let wallet = h.miner.clone_for_test(0);
    let tx = common::spend_first_coin(&mut h, &wallet, &other.address, 1_000);
    let txid = tx.txid();
    assert_eq!(h.chain.store().transaction_location(&txid).unwrap(), None);
    let block = h.extend(vec![tx.clone()]);
    let height = block.header().height;
    let store = h.chain.store();
    assert_eq!(
        store.transaction_location(&txid).unwrap(),
        Some((height, 1))
    );
    let coinbase = block.transactions()[0].txid();
    assert_eq!(
        store.transaction_location(&coinbase).unwrap(),
        Some((height, 0))
    );
    let (found, at, index) = store.transaction(&txid).unwrap().unwrap();
    assert_eq!((found.to_vec(), at, index), (tx.to_vec(), height, 1));
    store.revert().unwrap();
    assert_eq!(store.transaction_location(&txid).unwrap(), None);
    assert_eq!(store.transaction(&coinbase).unwrap(), None);
}

#[test]
fn interrupted_reorg_restores_real_transaction_indexes_and_tree() {
    let mut h = Harness::new(8801);
    let fork = h.chain.tip().unwrap().hash;
    let first = h.extend(Vec::new());
    let second = h.extend(Vec::new());
    let expected_root = h.chain.store().tree().unwrap().root();
    h.chain.store().begin_reorg(second.hash(), fork).unwrap();
    h.chain.store().revert().unwrap();
    h.chain.store().revert().unwrap();
    // Recovery must run even when the arriving block is already stored.
    assert_eq!(h.import(&second).unwrap(), Import::AlreadyKnown);
    assert_eq!(h.chain.tip().unwrap().hash, second.hash());
    assert_eq!(h.chain.store().tree().unwrap().root(), expected_root);
    for block in [&first, &second] {
        for (index, tx) in block.transactions().iter().enumerate() {
            assert_eq!(
                h.chain.store().transaction_location(&tx.txid()).unwrap(),
                Some((block.header().height, index as u32))
            );
            for nf in tx.nullifiers() {
                assert!(h.chain.store().contains_nullifier(nf).unwrap());
            }
        }
    }
    assert!(h.chain.store().pending_reorg().unwrap().is_none());
}

#[test]
fn failed_reorg_restores_original_chain_and_clears_journal() {
    let mut h = Harness::with_params(
        8802,
        ChainParams {
            max_reorg_depth: 1,
            ..ChainParams::test()
        },
    );
    let fork = h.tip_header();
    let fork_tree = h.chain.store().tree().unwrap();
    let main = h.extend(Vec::new());
    let (side, side_tree) = h.make_block_on(&fork, &fork_tree, Vec::new());
    let side = mine_below_tip(&h, &side, main.hash());
    assert_eq!(h.import(&side).unwrap(), Import::SideChain);
    let (bad, _) = h.make_block_on(side.header(), &side_tree, Vec::new());
    let mut header = bad.header().clone();
    header.commitment_root = side_tree.root();
    assert!(h.chain.pow().mine(&mut header, 256, &mut h.rng).unwrap());
    let bad = Block::new(header, bad.transactions().to_vec());
    assert!(matches!(
        h.import(&bad),
        Err(Error::InvalidHeader("commitment root mismatch"))
    ));
    assert_eq!(h.chain.tip().unwrap().hash, main.hash());
    assert_eq!(
        h.chain.store().tree().unwrap().root(),
        main.header().commitment_root
    );
    assert!(h.chain.store().pending_reorg().unwrap().is_none());
    for tx in main.transactions() {
        assert!(h
            .chain
            .store()
            .transaction_location(&tx.txid())
            .unwrap()
            .is_some());
        for nf in tx.nullifiers() {
            assert!(h.chain.store().contains_nullifier(nf).unwrap());
        }
    }
    for tx in side.transactions() {
        assert!(h
            .chain
            .store()
            .transaction_location(&tx.txid())
            .unwrap()
            .is_none());
        for nf in tx.nullifiers() {
            assert!(!h.chain.store().contains_nullifier(nf).unwrap());
        }
    }
}

/// Tiny-block baseline only: excludes coinbase proving, mining, and wallet scans.
#[test]
#[ignore = "measurement, not a check"]
fn coinbase_only_block_import_timing() {
    let mut h = Harness::new(9841);
    let mut samples = Vec::with_capacity(7);
    for _ in 0..7 {
        let parent = h.tip_header();
        let block = h.make_block(&parent, Vec::new());
        let started = std::time::Instant::now();
        let imported = h.import(&block);
        samples.push(started.elapsed());
        assert_eq!(imported.unwrap(), Import::Extended);
    }
    let mut ordered = samples.clone();
    ordered.sort_unstable();
    eprintln!(
        "tiny coinbase-only block import: median {:?}, samples {samples:?}",
        ordered[3]
    );
}

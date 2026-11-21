//! Stateless transaction validation.
//!
//! Stateless means: everything that can be checked from the transaction
//! bytes alone, including the proof. Anchor validity and nullifier
//! freshness belong to the chain layer.

use std::collections::BTreeSet;

use crypto::signature::{BatchVerifier, BindingVerificationKey};
use rand_core::{CryptoRng, RngCore};
use transaction_proof::{ProofBatch, VerifyingKey};

use crate::consensus::{
    is_action_class, proof_len, BranchId, COINBASE_KIND, TRANSFER_KIND, TX_VERSION,
};
use crate::transaction::Transaction;
use crate::{Error, Result};

/// Checks shape rules: version, action class, proof length, unique nullifiers,
/// and the minimum encoded-size fee.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] naming the first violated rule, or
/// [`Error::RawCoinOutOfRange`] if the fee cannot fit the binding balance.
pub fn check_structure(tx: &Transaction) -> Result<()> {
    check_transfer_shape(tx)?;
    tx.check_fee()?;
    Ok(())
}

/// Checks transfer encoding shape without checking its fee or authorization.
/// Stateful admission checks anchors and nullifiers after this inexpensive
/// pass, then checks the fee before verifying signatures and the proof.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] for a malformed transfer shape.
pub fn check_transfer_shape(tx: &Transaction) -> Result<()> {
    check_shape_and_kind(tx, TRANSFER_KIND)
}

/// Checks coinbase encoding shape without checking its zero-fee rule.
/// The caller must classify the coinbase by its position in the block.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] for a malformed coinbase shape.
pub fn check_coinbase_shape(tx: &Transaction) -> Result<()> {
    check_shape_and_kind(tx, COINBASE_KIND)
}

/// Checks the structural shape used by kernel-created coinbases.
///
/// This must only be called after the chain kernel has classified the
/// transaction as a coinbase and computed its public balance.
pub fn check_coinbase_structure(tx: &Transaction) -> Result<()> {
    check_coinbase_shape(tx)?;
    tx.check_fee()
}

fn check_shape_and_kind(tx: &Transaction, kind: u8) -> Result<()> {
    if tx.version() != TX_VERSION {
        return Err(Error::InvalidTransaction("unknown version"));
    }
    if tx.kind() != kind {
        return Err(Error::InvalidTransaction("wrong native transaction kind"));
    }
    if !is_action_class(tx.actions().len()) {
        return Err(Error::InvalidTransaction(
            "action count is not an allowed class",
        ));
    }
    if tx.proof().as_bytes().len() != proof_len(tx.actions().len())? {
        return Err(Error::InvalidTransaction(
            "proof length does not match action count",
        ));
    }
    let mut seen = BTreeSet::new();
    if !tx.nullifiers().all(|nf| seen.insert(*nf)) {
        return Err(Error::InvalidTransaction("duplicate nullifier"));
    }
    Ok(())
}

/// The public value balance of a coinbase paying `credit` (net issuance plus
/// the fees paid by transfers): it creates value in the coinbase transaction.
///
/// # Errors
/// If `credit` does not fit an `i64`.
pub fn coinbase_balance(credit: crate::amount::RawCoin) -> Result<i64> {
    credit
        .to_i64()?
        .checked_neg()
        .ok_or(Error::RawCoinOutOfRange)
}

/// Queues every transaction signature into `batch` for later verification.
/// `balance` is the public value balance the binding signature must prove;
/// `branch` is the consensus branch in force where the transaction is being
/// validated, which the signatures must have been made for.
///
/// # Errors
/// Fails if the binding verification key cannot be derived.
fn queue_signatures(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    let sighash = tx.sighash(branch);
    for action in tx.actions() {
        batch.queue_spend_auth(action.body().rk(), action.spend_auth_sig(), &sighash);
    }
    let bvk = BindingVerificationKey::from_commitments(tx.value_commitments(), balance)?;
    batch.queue_binding(&bvk, tx.binding_signature(), &sighash);
    Ok(())
}

/// Queues both signature classes for a transfer using its declared public fee.
pub fn queue_transfer_signatures(
    tx: &Transaction,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    check_structure(tx)?;
    queue_signatures(tx, tx.fee().to_i64()?, branch, batch)
}

/// Queues signatures for a call classified as a coinbase by consensus.
pub fn queue_coinbase_signatures(
    tx: &Transaction,
    mint: crate::amount::RawCoin,
    branch: BranchId,
    batch: &mut BatchVerifier,
) -> Result<()> {
    check_coinbase_structure(tx)?;
    queue_signatures(tx, coinbase_balance(mint)?, branch, batch)
}

/// Queues a transfer's signatures against its declared fee, then its proof.
pub fn queue_transfer(
    tx: &Transaction,
    branch: BranchId,
    signatures: &mut BatchVerifier,
    proofs: &mut ProofBatch,
) -> Result<()> {
    check_structure(tx)?;
    queue_spend_auth_and_binding(tx, tx.fee().to_i64()?, branch, signatures)?;
    queue_proof(tx, proofs)
}

/// Queues spend-auth and binding signatures after the caller has checked shape.
pub fn queue_checked_signatures(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    signatures: &mut BatchVerifier,
) -> Result<()> {
    queue_spend_auth_and_binding(tx, balance, branch, signatures)
}

fn queue_spend_auth_and_binding(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    signatures: &mut BatchVerifier,
) -> Result<()> {
    queue_signatures(tx, balance, branch, signatures)
}

/// Queues signatures and proof for coinbase against validator-computed mint.
pub fn queue_coinbase(
    tx: &Transaction,
    mint: crate::amount::RawCoin,
    branch: BranchId,
    signatures: &mut BatchVerifier,
    proofs: &mut ProofBatch,
) -> Result<()> {
    check_coinbase_structure(tx)?;
    queue_spend_auth_and_binding(tx, coinbase_balance(mint)?, branch, signatures)?;
    queue_coinbase_proof(tx, proofs)
}

/// Queues the proof of `tx` into `batch` for later verification.
///
/// # Errors
/// Fails if an action carries a non-canonical point.
pub fn queue_proof(tx: &Transaction, batch: &mut ProofBatch) -> Result<()> {
    queue_proof_with_kind(tx, false, batch)
}

/// Queues a block-position-classified coinbase proof.
pub fn queue_coinbase_proof(tx: &Transaction, batch: &mut ProofBatch) -> Result<()> {
    queue_proof_with_kind(tx, true, batch)
}

fn queue_proof_with_kind(tx: &Transaction, coinbase: bool, batch: &mut ProofBatch) -> Result<()> {
    if tx.action_proof_envelope().is_none() {
        return Err(Error::InvalidTransaction(
            "action proof envelope is missing",
        ));
    }
    Ok(batch.add(tx.proof(), &tx.public_inputs(coinbase)?)?)
}

/// Verifies the proof of one transaction on its own.
///
/// # Errors
/// Returns [`transaction_proof::Error::InvalidProof`] if the proof is wrong.
pub fn verify_proof(tx: &Transaction, vk: &VerifyingKey) -> Result<()> {
    tx.action_proof_envelope()
        .ok_or(Error::InvalidTransaction(
            "action proof envelope is missing",
        ))?
        .verify(vk, &tx.public_inputs(tx.kind() == COINBASE_KIND)?)?;
    Ok(())
}

/// Verifies using the public balance computed by native transaction or
/// block consensus rules.
///
/// # Errors
/// Returns the first violation found.
pub fn verify_transfer(
    tx: &Transaction,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    check_structure(tx)?;
    verify_authorization_and_proof(tx, tx.fee().to_i64()?, branch, vk, rng)
}

/// Verifies a coinbase against the validator-computed mint.
pub fn verify_coinbase(
    tx: &Transaction,
    mint: crate::amount::RawCoin,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    check_coinbase_structure(tx)?;
    verify_authorization_and_proof(tx, coinbase_balance(mint)?, branch, vk, rng)
}

fn verify_authorization_and_proof(
    tx: &Transaction,
    balance: i64,
    branch: BranchId,
    vk: &VerifyingKey,
    rng: &mut (impl RngCore + CryptoRng),
) -> Result<()> {
    let mut batch = BatchVerifier::new();
    queue_signatures(tx, balance, branch, &mut batch)?;
    batch.verify(rng)?;
    verify_proof(tx, vk)
}

#[cfg(test)]
mod tests {
    use crypto::signature::BindingSignature;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use transaction_proof::ActionProofEnvelope;

    use super::*;
    use crate::action::tests::sample_action;
    use crate::action::ACTION_BODY_LEN;
    use crate::bytes::Encodable;
    use crate::test_keys;
    use crate::transaction::tests::{dummy_proof, sample_anchor};

    fn unsigned_tx(seed: u64, count: usize) -> Transaction {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let actions = (0..count).map(|_| sample_action(&mut rng, b"x")).collect();
        let action_proof = if proof_len(count).is_err() {
            crate::transaction::Proof::from_bytes(vec![0])
        } else {
            dummy_proof(count)
        };
        let envelope = ActionProofEnvelope::new(&action_proof).unwrap();
        let fee = crate::consensus::proof_len(count)
            .and_then(|_| Transaction::encoded_len_for_actions(count))
            .and_then(crate::fee::fee_for_len)
            .unwrap_or(crate::amount::RawCoin::ZERO);
        Transaction::new(
            sample_anchor(),
            fee,
            actions,
            envelope,
            BindingSignature::from_bytes([0; 64]),
        )
        .unwrap()
    }

    #[test]
    fn structure_accepts_every_class() {
        for class in [2, 4, 8, 16] {
            assert!(check_structure(&unsigned_tx(1, class)).is_ok());
        }
    }

    #[test]
    fn structure_rejects_bad_action_counts() {
        for count in [0, 1, 3, 17] {
            assert!(matches!(
                check_structure(&unsigned_tx(2, count)),
                Err(Error::InvalidTransaction(
                    "action count is not an allowed class"
                ))
            ));
        }
    }

    #[test]
    fn structure_rejects_wrong_proof_length() {
        let mut rng = ChaCha20Rng::seed_from_u64(9);
        let actions = (0..2).map(|_| sample_action(&mut rng, b"x")).collect();
        let envelope = ActionProofEnvelope::new(&dummy_proof(4)).unwrap();
        let tx = Transaction::new(
            sample_anchor(),
            crate::amount::RawCoin::ZERO,
            actions,
            envelope,
            BindingSignature::from_bytes([0; 64]),
        )
        .unwrap();
        assert!(matches!(
            check_structure(&tx),
            Err(Error::InvalidTransaction(
                "proof length does not match action count"
            ))
        ));
    }

    #[test]
    fn structure_rejects_unknown_version() {
        let mut bytes = unsigned_tx(3, 2).to_vec();
        bytes[0] = TX_VERSION.wrapping_add(1);
        assert!(Transaction::from_slice(&bytes).is_err());
    }

    #[test]
    fn structure_rejects_duplicate_nullifiers() {
        let tx = unsigned_tx(4, 2);
        let mut bytes = tx.to_vec();
        let first = 1 + 1 + 32 + 8 + 1;
        let second = first + ACTION_BODY_LEN;
        let nf: Vec<u8> = bytes[first..first + 32].to_vec();
        bytes[second..second + 32].copy_from_slice(&nf);
        let dup = Transaction::from_slice(&bytes).unwrap();
        assert!(matches!(
            check_structure(&dup),
            Err(Error::InvalidTransaction("duplicate nullifier"))
        ));
    }

    #[test]
    fn structure_enforces_minimum_fee_and_native_transfer_kind() {
        let tx = unsigned_tx(41, 2);
        assert!(check_structure(&tx).is_ok());

        let mut bytes = tx.to_vec();
        let fee_offset = 1 + 1 + 32;
        let original = tx.fee().raw();
        bytes[fee_offset..fee_offset + 8].copy_from_slice(&(original - 1).to_le_bytes());
        let wrong_fee = Transaction::from_slice(&bytes).unwrap();
        assert!(check_transfer_shape(&wrong_fee).is_ok());
        assert!(matches!(
            check_structure(&wrong_fee),
            Err(Error::InvalidTransaction(
                "fee is below transaction minimum"
            ))
        ));

        let mut bytes = tx.to_vec();
        bytes[fee_offset..fee_offset + 8].copy_from_slice(&(original + 1).to_le_bytes());
        let above_minimum = Transaction::from_slice(&bytes).unwrap();
        assert!(check_structure(&above_minimum).is_ok());

        let mut bytes = tx.to_vec();
        bytes[1] = COINBASE_KIND;
        let wrong_kind = Transaction::from_slice(&bytes).unwrap();
        assert!(matches!(
            check_structure(&wrong_kind),
            Err(Error::InvalidTransaction("wrong native transaction kind"))
        ));
    }

    #[test]
    fn decoded_extreme_fees_are_rejected_before_authorization() {
        let tx = unsigned_tx(42, 2);
        for fee in [i64::MAX as u64 + 1, u64::MAX] {
            let mut bytes = tx.to_vec();
            let fee_offset = 1 + 1 + 32;
            bytes[fee_offset..fee_offset + 8].copy_from_slice(&fee.to_le_bytes());
            let decoded = Transaction::from_slice(&bytes).unwrap();
            assert_eq!(decoded.fee().raw(), fee);
            assert!(matches!(
                check_structure(&decoded),
                Err(Error::RawCoinOutOfRange)
            ));
        }
    }

    #[test]
    fn coinbase_balance_rejects_unsigned_values_outside_signed_range() {
        use crate::amount::RawCoin;

        assert_eq!(coinbase_balance(RawCoin::ZERO), Ok(0));
        assert_eq!(
            coinbase_balance(RawCoin::from_raw(i64::MAX as u64).unwrap()),
            Ok(-i64::MAX)
        );
        for raw in [i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(
                coinbase_balance(RawCoin::from_raw(raw).unwrap()),
                Err(Error::RawCoinOutOfRange)
            );
        }
    }

    #[test]
    fn signatures_over_the_wrong_message_fail() {
        // sample_action signs "x", not the real sighash.
        let tx = unsigned_tx(5, 2);
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        assert!(matches!(
            verify_transfer(&tx, BranchId::new(1), test_keys::verifying_key(), &mut rng),
            Err(Error::Crypto(crypto::Error::InvalidSignature))
        ));
    }

    #[test]
    fn zero_proof_is_rejected_even_with_valid_structure() {
        let tx = unsigned_tx(7, 2);
        assert!(matches!(
            verify_proof(&tx, test_keys::verifying_key()),
            Err(Error::Circuit(transaction_proof::Error::InvalidProof))
        ));
        let mut batch = ProofBatch::new();
        queue_proof(&tx, &mut batch).unwrap();
        assert!(batch.verify(test_keys::verifying_key()).is_err());
    }
}

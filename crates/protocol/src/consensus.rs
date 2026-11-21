//! Consensus constants for transaction shape, issuance and size limits.
//! Fees are public, deterministic transaction fields and block reward
//! conservation is checked by each transaction's value-binding signature.

use crate::amount::{RawCoin, RAWCOIN};
use crate::{Error, Result};

/// Native chain transaction format with recipient-only encrypted outputs.
pub const TX_VERSION: u8 = 1;
/// Native transaction kind: shielded transfer.
pub const TRANSFER_KIND: u8 = 0;
/// Coinbase kind. Consensus also requires this transaction at block index 0.
pub const COINBASE_KIND: u8 = 1;

/// Current and only block-header encoding.
pub const BLOCK_VERSION: u8 = 1;

/// Identifies one set of consensus rules. Every signature hash binds the
/// branch in force at the block's height, so a transaction signed under
/// one set of rules is invalid under any other: after a fork neither side
/// can replay the other's transactions, and a test network transaction
/// is never valid on the main network. The branch is not part of the
/// transaction bytes; validation supplies it from the chain parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BranchId(u32);

impl BranchId {
    /// Wraps a raw identifier.
    pub const fn new(id: u32) -> Self {
        Self(id)
    }

    /// The bytes hashed into a sighash.
    pub const fn to_bytes(self) -> [u8; 4] {
        self.0.to_le_bytes()
    }
}

/// Byte length of the RandomX proof-of-work hash stored in a block header.
pub const POW_SOLUTION_LEN: usize = 32;

/// Most transactions a block may carry. Provisional.
pub const MAX_BLOCK_TRANSACTIONS: usize = 512;

/// Initial block reward: 25 coins.
pub const INITIAL_EMISSION: u64 = 25 * RAWCOIN;
/// Tail subsidy ceiling before the per-block fee offset: 0.25 coins.
pub const TAIL_EMISSION: u64 = RAWCOIN / 4;
/// Last block paid the initial reward; the tail starts at height 525,601.
pub const TAIL_HEIGHT: u64 = 525_600;
/// Total initial-reward issuance through [`TAIL_HEIGHT`], excluding fees.
pub const TARGET_MINED: u64 = 13_140_000 * RAWCOIN;

/// Scheduled subsidy at `height`, before the tail fee offset. Genesis pays nothing.
/// [`crate::fee::net_issuance`] computes the actual newly issued amount.
pub fn subsidy(height: u32) -> RawCoin {
    if height == 0 {
        return RawCoin::ZERO;
    }
    let raw = if u64::from(height) > TAIL_HEIGHT {
        TAIL_EMISSION
    } else {
        INITIAL_EMISSION
    };
    RawCoin::from_raw(raw).unwrap_or(RawCoin::ZERO)
}

/// The height of the block after one at `height`.
///
/// # Errors
/// Returns [`Error::HeightExhausted`] at `u32::MAX`: the chain has no
/// defined continuation, so producing or importing a block there is
/// refused rather than letting a saturated height overwrite the index.
pub fn next_height(height: u32) -> Result<u32> {
    height.checked_add(1).ok_or(Error::HeightExhausted)
}

/// Allowed numbers of actions per transaction. A transaction is padded with
/// dummy actions up to the smallest class that fits.
pub const ACTION_CLASSES: [usize; 4] = [2, 4, 8, 16];

/// The largest action class.
pub const MAX_ACTIONS: usize = 16;

/// The exact proof length of a bundle with `actions` actions.
///
/// # Errors
/// Returns [`Error::InvalidTransaction`] if `actions` is not a class.
pub fn proof_len(actions: usize) -> Result<usize> {
    transaction_proof::proof_len(actions).ok_or(Error::InvalidTransaction(
        "action count is not an allowed class",
    ))
}

/// The smallest action class that fits `needed` actions.
///
/// # Errors
/// Returns [`Error::TooManyActions`] above [`MAX_ACTIONS`].
pub fn action_class_for(needed: usize) -> Result<usize> {
    ACTION_CLASSES
        .iter()
        .copied()
        .find(|class| *class >= needed)
        .ok_or(Error::TooManyActions)
}

/// Whether `count` is an allowed number of actions.
pub fn is_action_class(count: usize) -> bool {
    ACTION_CLASSES.contains(&count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classes_are_ascending_powers_of_two_up_to_max() {
        assert_eq!(ACTION_CLASSES.last(), Some(&MAX_ACTIONS));
        for window in ACTION_CLASSES.windows(2) {
            assert_eq!(window[0] * 2, window[1]);
        }
    }

    #[test]
    fn class_is_the_smallest_that_fits() {
        assert_eq!(action_class_for(0), Ok(2));
        assert_eq!(action_class_for(1), Ok(2));
        assert_eq!(action_class_for(2), Ok(2));
        assert_eq!(action_class_for(3), Ok(4));
        assert_eq!(action_class_for(9), Ok(16));
        assert_eq!(action_class_for(16), Ok(16));
        assert_eq!(action_class_for(17), Err(Error::TooManyActions));
    }

    #[test]
    fn branch_ids_encode_little_endian_and_compare_by_value() {
        assert_eq!(BranchId::new(0x0403_0201).to_bytes(), [1, 2, 3, 4]);
        assert_eq!(BranchId::new(7), BranchId::new(7));
        assert_ne!(BranchId::new(7), BranchId::new(8));
    }

    #[test]
    fn next_height_counts_up_and_refuses_exhaustion() {
        assert_eq!(next_height(0), Ok(1));
        assert_eq!(next_height(u32::MAX - 1), Ok(u32::MAX));
        assert_eq!(next_height(u32::MAX), Err(Error::HeightExhausted));
    }

    #[test]
    fn membership_matches_classes() {
        assert!(is_action_class(4));
        assert!(!is_action_class(3));
        assert!(!is_action_class(0));
    }

    #[test]
    fn proof_len_exists_exactly_for_classes() {
        for class in ACTION_CLASSES {
            assert!(proof_len(class).is_ok());
        }
        assert!(proof_len(3).is_err());
    }

    #[test]
    fn emission_switches_to_the_tail_after_the_target_initial_issuance() {
        assert_eq!(subsidy(0), RawCoin::ZERO);
        assert_eq!(INITIAL_EMISSION, 2_500_000_000);
        assert_eq!(TAIL_EMISSION, 25_000_000);
        assert_eq!(TAIL_HEIGHT, 525_600);
        assert_eq!(TARGET_MINED, 1_314_000_000_000_000);
        assert_eq!(INITIAL_EMISSION * TAIL_HEIGHT, TARGET_MINED);
        assert_eq!(subsidy(1).raw(), INITIAL_EMISSION);
        assert_eq!(subsidy(525_599).raw(), INITIAL_EMISSION);
        assert_eq!(subsidy(525_600).raw(), INITIAL_EMISSION);
        assert_eq!(subsidy(525_601).raw(), TAIL_EMISSION);
        assert_eq!(subsidy(u32::MAX).raw(), TAIL_EMISSION);
    }
}

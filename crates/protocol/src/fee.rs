//! Public transaction fee, priced per encoded byte.

use crate::amount::RawCoin;
use crate::consensus::{subsidy, TAIL_HEIGHT};
use crate::{Error, Result};

/// Price per encoded byte, in rawcoin.
pub const FEE_PER_BYTE: u64 = 1;

/// Fee for a transaction whose exact encoded length is `len`.
pub fn fee_for_len(len: usize) -> Result<RawCoin> {
    let len = u64::try_from(len).map_err(|_| Error::InvalidTransaction("fee overflow"))?;
    let raw = FEE_PER_BYTE
        .checked_mul(len)
        .ok_or(Error::InvalidTransaction("fee overflow"))?;
    RawCoin::from_raw(raw)
}

/// Sum of the fees declared by a block's transactions, overflow-checked.
pub fn total_fees(fees: impl IntoIterator<Item = RawCoin>) -> Result<RawCoin> {
    let mut total = 0u64;
    for fee in fees {
        total = total
            .checked_add(fee.raw())
            .ok_or(Error::InvalidBlock("fee sum overflow"))?;
    }
    RawCoin::from_raw(total)
}

/// Newly issued value at `height`, after the tail subsidy's fee offset.
/// Initial issuance is unchanged. In the tail phase, fees replace subsidy
/// until the newly issued amount reaches zero; this is recomputed per block.
pub fn net_issuance(height: u32, transfer_fees: RawCoin) -> Result<RawCoin> {
    let scheduled = subsidy(height);
    if u64::from(height) > TAIL_HEIGHT {
        RawCoin::from_raw(scheduled.raw().saturating_sub(transfer_fees.raw()))
    } else {
        Ok(scheduled)
    }
}

/// Coinbase payout: newly issued value plus every included transfer fee.
/// During the tail phase this is the larger of the scheduled tail subsidy
/// and total fees. Fees above the tail ceiling are paid in full, not burned.
pub fn block_mint(
    height: u32,
    transfer_fees: impl IntoIterator<Item = RawCoin>,
) -> Result<RawCoin> {
    let fees = total_fees(transfer_fees)?;
    net_issuance(height, fees)?.checked_add(fees)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_is_one_raw_unit_per_byte() {
        assert_eq!(fee_for_len(2_048).unwrap().raw(), 2_048);
    }

    #[test]
    fn total_fees_rejects_overflow() {
        let max = RawCoin::from_raw(u64::MAX >> 1).unwrap();
        assert!(total_fees([max, max, max]).is_err());
    }

    #[test]
    fn total_fees_sums_values() {
        let fees = [RawCoin::from_raw(3).unwrap(), RawCoin::from_raw(5).unwrap()];
        assert_eq!(total_fees(fees).unwrap().raw(), 8);
    }

    #[test]
    fn block_mint_adds_subsidy_and_transfer_fees() {
        let fees = [
            RawCoin::from_raw(7).unwrap(),
            RawCoin::from_raw(11).unwrap(),
        ];
        assert_eq!(block_mint(1, fees).unwrap().raw(), subsidy(1).raw() + 18);
        assert!(block_mint(1, [RawCoin::MAX]).is_err());
    }

    #[test]
    fn fee_offset_starts_only_after_the_last_initial_block() {
        use crate::consensus::{INITIAL_EMISSION, TAIL_EMISSION};

        let last_initial = u32::try_from(TAIL_HEIGHT).unwrap();
        for height in [1, last_initial] {
            for fees in [0, TAIL_EMISSION - 1, TAIL_EMISSION, TAIL_EMISSION + 1] {
                let fees = RawCoin::from_raw(fees).unwrap();
                assert_eq!(net_issuance(height, fees).unwrap().raw(), INITIAL_EMISSION);
                assert_eq!(
                    block_mint(height, [fees]).unwrap().raw(),
                    INITIAL_EMISSION + fees.raw()
                );
            }
        }
        assert_eq!(net_issuance(0, RawCoin::MAX).unwrap(), RawCoin::ZERO);
    }

    #[test]
    fn tail_fees_replace_issuance_and_all_fees_reach_the_miner() {
        use crate::consensus::TAIL_EMISSION;

        let first_tail = u32::try_from(TAIL_HEIGHT).unwrap() + 1;
        for height in [first_tail, u32::MAX] {
            for fees in [
                0,
                1,
                TAIL_EMISSION - 1,
                TAIL_EMISSION,
                TAIL_EMISSION + 1,
                2 * TAIL_EMISSION,
                i64::MAX as u64,
                u64::MAX,
            ] {
                let amount = RawCoin::from_raw(fees).unwrap();
                let issued = net_issuance(height, amount).unwrap();
                let paid = block_mint(height, [amount]).unwrap();
                assert_eq!(issued.raw(), TAIL_EMISSION.saturating_sub(fees));
                assert_eq!(paid.raw(), TAIL_EMISSION.max(fees));
                assert_eq!(paid.checked_sub(amount).unwrap(), issued);
                assert!(issued.raw() <= TAIL_EMISSION);
            }
        }
    }

    #[test]
    fn tail_offset_uses_the_aggregate_fee_and_resets_for_each_block() {
        use crate::consensus::TAIL_EMISSION;

        let height = u32::try_from(TAIL_HEIGHT).unwrap() + 1;
        let half = RawCoin::from_raw(TAIL_EMISSION / 2).unwrap();
        let one = RawCoin::from_raw(1).unwrap();
        assert_eq!(
            block_mint(height, [half, half, one]).unwrap().raw(),
            TAIL_EMISSION + 1
        );
        assert_eq!(block_mint(height + 1, []).unwrap().raw(), TAIL_EMISSION);
        assert_eq!(
            net_issuance(height + 1, RawCoin::ZERO).unwrap().raw(),
            TAIL_EMISSION
        );
        assert_eq!(
            block_mint(height, [RawCoin::MAX, one]),
            Err(Error::InvalidBlock("fee sum overflow"))
        );
    }
}

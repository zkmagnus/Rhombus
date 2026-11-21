//! Monetary amounts represented as unsigned 64-bit values. [`ValueSum`] is a
//! signed running total used when checking that a transaction balances.

use core::ops::{Add, Sub};

use crate::{Error, Result};

/// Number of decimal places in one coin.
pub const DECIMAL: u32 = 8;
/// Smallest unit: one hundred-millionth of a coin.
pub const RAWCOIN: u64 = 100_000_000;

/// A non-negative amount represented as a `u64`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RawCoin(u64);

impl RawCoin {
    /// Zero.
    pub const ZERO: Self = Self(0);
    /// The maximum representable amount.
    pub const MAX: Self = Self(u64::MAX);

    /// Wraps a raw value.
    ///
    /// # Errors
    /// Every `u64` is representable; retained as a fallible constructor for API compatibility.
    pub fn from_raw(raw: u64) -> Result<Self> {
        Ok(Self(raw))
    }

    /// The raw value in smallest units.
    pub fn raw(self) -> u64 {
        self.0
    }

    /// Converts to a signed balance when representable.
    pub fn to_i64(self) -> Result<i64> {
        i64::try_from(self.0).map_err(|_| Error::RawCoinOutOfRange)
    }

    /// Little-endian encoding, used inside coin commitments.
    pub fn to_le_bytes(self) -> [u8; 8] {
        self.0.to_le_bytes()
    }

    /// Checked addition.
    ///
    /// # Errors
    /// Returns [`Error::RawCoinOutOfRange`] if the sum overflows `u64`.
    pub fn checked_add(self, other: Self) -> Result<Self> {
        self.0
            .checked_add(other.0)
            .map(Self)
            .ok_or(Error::RawCoinOutOfRange)
    }

    /// Checked subtraction.
    ///
    /// # Errors
    /// Returns [`Error::RawCoinOutOfRange`] if the result would be negative.
    pub fn checked_sub(self, other: Self) -> Result<Self> {
        self.0
            .checked_sub(other.0)
            .map(Self)
            .ok_or(Error::RawCoinOutOfRange)
    }
}

impl TryFrom<u64> for RawCoin {
    type Error = Error;
    fn try_from(raw: u64) -> Result<Self> {
        Self::from_raw(raw)
    }
}

impl From<RawCoin> for u64 {
    fn from(amount: RawCoin) -> Self {
        amount.raw()
    }
}

/// A signed sum of amounts stored in `i128`.
///
/// Up to `2^63` contributions of magnitude at most `u64::MAX` fit in `i128`.
/// The transaction builder bounds each side to [`crate::consensus::MAX_ACTIONS`]
/// amounts, so its sums and their difference are safely within that range.
/// These unchecked helpers and operators require callers to keep every result
/// representable; arbitrarily composing existing sums can exceed this bound.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct ValueSum(i128);

impl ValueSum {
    /// Zero.
    pub const ZERO: Self = Self(0);

    /// Whether the sum is exactly zero, i.e. inputs equal outputs.
    pub fn is_balanced(self) -> bool {
        self.0 == 0
    }

    /// The raw signed value.
    pub fn raw(self) -> i128 {
        self.0
    }

    /// Sums amounts into a signed total under the bound in the type doc.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    pub fn sum(amounts: impl IntoIterator<Item = RawCoin>) -> Self {
        amounts
            .into_iter()
            .fold(Self::ZERO, |acc, amount| acc + amount)
    }

    /// `self - other`.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn minus_sum(self, other: Self) -> Self {
        Self(self.0 - other.0)
    }

    /// `self - amount`, by value.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn minus(self, amount: RawCoin) -> Self {
        self - amount
    }

    /// `self + amount`, by value.
    #[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
    #[must_use]
    pub fn plus(self, amount: RawCoin) -> Self {
        self + amount
    }

    /// Converts to an `i64` for value commitments.
    ///
    /// # Errors
    /// Returns [`Error::RawCoinOutOfRange`] if the magnitude exceeds `i64`.
    pub fn to_i64(self) -> Result<i64> {
        i64::try_from(self.0).map_err(|_| Error::RawCoinOutOfRange)
    }
}

#[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
impl Add<RawCoin> for ValueSum {
    type Output = Self;
    fn add(self, rhs: RawCoin) -> Self {
        Self(self.0 + i128::from(rhs.0))
    }
}

#[allow(clippy::arithmetic_side_effects)] // see type-level doc on overflow
impl Sub<RawCoin> for ValueSum {
    type Output = Self;
    fn sub(self, rhs: RawCoin) -> Self {
        Self(self.0 - i128::from(rhs.0))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn amt(raw: u64) -> RawCoin {
        RawCoin::from_raw(raw).unwrap()
    }

    #[test]
    fn decimal_scale_matches_rawcoin() {
        assert_eq!(10u64.pow(DECIMAL), RAWCOIN);
    }

    #[test]
    fn full_u64_amount_range_is_representable() {
        assert_eq!(RawCoin::from_raw(u64::MAX), Ok(RawCoin::MAX));
        assert_eq!(RawCoin::try_from(0), Ok(RawCoin::ZERO));
    }

    #[test]
    fn signed_conversion_rejects_values_above_i64_max() {
        assert_eq!(amt(i64::MAX as u64).to_i64(), Ok(i64::MAX));
        for raw in [i64::MAX as u64 + 1, u64::MAX] {
            assert_eq!(amt(raw).to_i64(), Err(Error::RawCoinOutOfRange));
        }
    }

    #[test]
    fn checked_add_detects_u64_overflow() {
        assert_eq!(amt(1).checked_add(amt(2)), Ok(amt(3)));
        assert_eq!(
            RawCoin::MAX.checked_add(amt(1)),
            Err(Error::RawCoinOutOfRange)
        );
    }

    #[test]
    fn checked_sub_rejects_negative() {
        assert_eq!(amt(3).checked_sub(amt(2)), Ok(amt(1)));
        assert_eq!(amt(2).checked_sub(amt(3)), Err(Error::RawCoinOutOfRange));
    }

    #[test]
    fn value_sum_balances_when_inputs_equal_outputs() {
        let sum = ValueSum::ZERO + amt(10) + amt(5) - amt(15);
        assert!(sum.is_balanced());
        assert_eq!(sum.to_i64(), Ok(0));
    }

    #[test]
    fn value_sum_helpers_match_operators() {
        let total = ValueSum::sum([amt(1), amt(2), amt(3)]);
        assert_eq!(total, ValueSum::ZERO + amt(1) + amt(2) + amt(3));
        assert_eq!(total.plus(amt(4)), total + amt(4));
        assert_eq!(total.minus_sum(ValueSum::sum([amt(6)])), ValueSum::ZERO);
        assert_eq!(total.minus(amt(6)), ValueSum::ZERO);
    }

    #[test]
    fn maximum_action_amounts_sum_exactly_without_narrowing() {
        let amounts = [RawCoin::MAX; crate::consensus::MAX_ACTIONS];
        let total = ValueSum::sum(amounts);
        let expected = i128::from(u64::MAX) * crate::consensus::MAX_ACTIONS as i128;
        assert_eq!(total.raw(), expected);
        assert_eq!(total.minus_sum(total), ValueSum::ZERO);
        assert_eq!(ValueSum::ZERO.minus_sum(total).raw(), -expected);
        assert_eq!(total.to_i64(), Err(Error::RawCoinOutOfRange));
    }

    #[test]
    fn value_sum_can_go_negative() {
        let sum = ValueSum::ZERO - amt(7);
        assert!(!sum.is_balanced());
        assert_eq!(sum.raw(), -7);
        assert_eq!(sum.to_i64(), Ok(-7));
    }

    #[test]
    fn le_bytes_match_raw() {
        assert_eq!(amt(0x0102).to_le_bytes(), [2, 1, 0, 0, 0, 0, 0, 0]);
        assert_eq!(u64::from(amt(9)), 9);
    }
}

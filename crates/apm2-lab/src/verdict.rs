use serde::{Deserialize, Serialize};

/// Three-valued verdict used by the lab closure rules.
///
/// Ordering is FAIL > PENDING > PASS, where `join` picks the maximum.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    Pass,
    Pending,
    Fail,
}

impl Default for Verdict {
    fn default() -> Self {
        Self::Pending
    }
}

impl Verdict {
    /// Join operation for the verdict semilattice.
    #[must_use]
    pub const fn join(self, other: Self) -> Self {
        if self.rank() >= other.rank() {
            self
        } else {
            other
        }
    }

    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Pass | Self::Fail)
    }

    #[must_use]
    const fn rank(self) -> u8 {
        match self {
            Self::Pass => 0,
            Self::Pending => 1,
            Self::Fail => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::Verdict;

    fn arb_verdict() -> impl Strategy<Value = Verdict> {
        prop_oneof![
            Just(Verdict::Pass),
            Just(Verdict::Pending),
            Just(Verdict::Fail),
        ]
    }

    proptest! {
        #[test]
        fn join_is_commutative(a in arb_verdict(), b in arb_verdict()) {
            prop_assert_eq!(a.join(b), b.join(a));
        }

        #[test]
        fn join_is_associative(a in arb_verdict(), b in arb_verdict(), c in arb_verdict()) {
            prop_assert_eq!(a.join(b).join(c), a.join(b.join(c)));
        }

        #[test]
        fn join_is_idempotent(a in arb_verdict()) {
            prop_assert_eq!(a.join(a), a);
        }

        #[test]
        fn fail_dominates(a in arb_verdict()) {
            prop_assert_eq!(a.join(Verdict::Fail), Verdict::Fail);
        }
    }
}

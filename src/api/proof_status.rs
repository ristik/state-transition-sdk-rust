//! The aggregator's proof status hint.

use core::fmt;

/// What an aggregator says about a state id when asked with `includeStatus`.
///
/// **This is an unauthenticated hint** for control flow and user feedback only:
/// the aggregator is not a trust anchor. `Unknown` is not proof of absence and
/// `Expired` is not proof that a state is unspent; a status never replaces,
/// influences or short-cuts verification of a proof, token or certificate, and
/// an `Included` hint is worth nothing without a proof that verifies.
///
/// Servers that predate the hint answer with a plain string (no status); callers
/// then get `None` and the legacy behavior. Values this version does not know are
/// treated the same way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ProofStatus {
    /// The aggregator reports the state certified in a published round.
    Included,
    /// Accepted by this aggregator and not yet in a published certified state:
    /// waiting (at round cadence) is meaningful.
    Pending,
    /// Admitted, then dropped because its effective timeout passed before
    /// inclusion. Waiting can not help; the same signed request may be resubmitted.
    Expired,
    /// Not seen at this node (never submitted here, misrouted, lost, or a restart
    /// or a different HA instance forgot it). May be transient right after a
    /// submission.
    Unknown,
}

impl ProofStatus {
    /// Parse the wire value; `None` for a value this version does not know
    /// (treated as "no status", i.e. legacy behavior).
    pub fn from_wire(value: &str) -> Option<Self> {
        match value {
            "included" => Some(ProofStatus::Included),
            "pending" => Some(ProofStatus::Pending),
            "expired" => Some(ProofStatus::Expired),
            "unknown" => Some(ProofStatus::Unknown),
            _ => None,
        }
    }

    /// The wire value.
    pub fn as_wire(self) -> &'static str {
        match self {
            ProofStatus::Included => "included",
            ProofStatus::Pending => "pending",
            ProofStatus::Expired => "expired",
            ProofStatus::Unknown => "unknown",
        }
    }
}

impl fmt::Display for ProofStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_wire())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_values_round_trip_and_unknown_values_are_no_status() {
        for s in [
            ProofStatus::Included,
            ProofStatus::Pending,
            ProofStatus::Expired,
            ProofStatus::Unknown,
        ] {
            assert_eq!(ProofStatus::from_wire(s.as_wire()), Some(s));
        }
        for v in ["", "Pending", "failed", "included "] {
            assert_eq!(ProofStatus::from_wire(v), None);
        }
    }
}

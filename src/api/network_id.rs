//! Network identifier (α) scoping token ids and other network-bound values.

use crate::error::Error;

/// A Unicity network identifier. Wraps a 16-bit unsigned value; the well-known
/// networks are provided as constants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct NetworkId(u16);

impl NetworkId {
    /// Production network (id 1).
    pub const MAINNET: NetworkId = NetworkId(1);
    /// The public test network, testnet2 (id 4). There is deliberately no constant for network 2, the
    /// old testnet that unicity-ids no longer lists: a name that looks like "the test network" must not
    /// be a different network. Use [`new`](Self::new) for any other id.
    pub const TESTNET2: NetworkId = NetworkId(4);
    /// Local/dev network (id 3).
    pub const LOCAL: NetworkId = NetworkId(3);

    /// Construct from a numeric id. The id must be in `1..=0xffff`.
    pub fn new(id: u16) -> Result<Self, Error> {
        if id == 0 {
            return Err(Error::OutOfRange("network id must be >= 1"));
        }
        Ok(NetworkId(id))
    }

    /// The numeric id.
    pub fn id(self) -> u16 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_named_networks_and_any_valid_id() {
        assert_eq!(NetworkId::MAINNET.id(), 1);
        assert_eq!(NetworkId::TESTNET2.id(), 4);
        assert_eq!(NetworkId::LOCAL.id(), 3);
        // any valid id is still accepted (network 2 included), only 0 is not
        assert_eq!(NetworkId::new(2).unwrap().id(), 2);
        assert_eq!(NetworkId::new(0xffff).unwrap().id(), 0xffff);
        assert!(NetworkId::new(0).is_err());
    }
}

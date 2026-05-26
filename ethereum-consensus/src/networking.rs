pub use multiaddr::Multiaddr;
use multihash::Multihash;
#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};
use thiserror::Error;

pub const MAX_INLINE_KEY_LENGTH: usize = 42;
const IDENTITY_CODE: u64 = 0x00;
const SHA2_256_CODE: u64 = 0x12;
type PeerMultihash = Multihash<64>;

// PeerId reimplemented from rust-libp2p
// revisit this implementation later
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PeerId {
    multihash: PeerMultihash,
}

impl fmt::Display for PeerId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_base58())
    }
}

impl PeerId {
    pub fn to_base58(&self) -> String {
        bs58::encode(self.multihash.to_bytes()).into_string()
    }
    /// Returns a raw bytes representation of this `PeerId`.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.multihash.to_bytes()
    }
    /// Parses a `PeerId` from bytes.
    pub fn from_bytes(data: &[u8]) -> Result<PeerId, PeerIdError> {
        let multihash = PeerMultihash::from_bytes(data)?;
        PeerId::from_multihash(multihash).map_err(|mh| PeerIdError::UnsupportedCode(mh.code()))
    }
    /// Tries to turn a `Multihash` into a `PeerId`.
    pub fn from_multihash(multihash: PeerMultihash) -> Result<PeerId, PeerMultihash> {
        match multihash.code() {
            SHA2_256_CODE => Ok(PeerId { multihash }),
            IDENTITY_CODE if multihash.digest().len() <= MAX_INLINE_KEY_LENGTH => {
                Ok(PeerId { multihash })
            }
            _ => Err(multihash),
        }
    }
}

#[cfg(feature = "serde")]
impl Serialize for PeerId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_base58())
        } else {
            serializer.serialize_bytes(&self.to_bytes()[..])
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> Deserialize<'de> for PeerId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::*;

        struct PeerIdVisitor;

        impl Visitor<'_> for PeerIdVisitor {
            type Value = PeerId;

            fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "valid peer id")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: Error,
            {
                PeerId::from_bytes(v).map_err(|_| Error::invalid_value(Unexpected::Bytes(v), &self))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: Error,
            {
                PeerId::from_str(v).map_err(|_| Error::invalid_value(Unexpected::Str(v), &self))
            }
        }

        if deserializer.is_human_readable() {
            deserializer.deserialize_str(PeerIdVisitor)
        } else {
            deserializer.deserialize_bytes(PeerIdVisitor)
        }
    }
}

#[derive(Debug, Error)]
pub enum PeerIdError {
    #[error("multihash decode error: {0}")]
    Multihash(#[from] multihash::Error),
    #[error("unsupported peer id multihash code: {0}")]
    UnsupportedCode(u64),
}

#[derive(Debug, Error)]
pub enum ParseError {
    #[error("base-58 decode error: {0}")]
    B58(#[from] bs58::decode::Error),
    #[error("peer id decode error: {0}")]
    PeerId(#[from] PeerIdError),
}

impl FromStr for PeerId {
    type Err = ParseError;

    #[inline]
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = bs58::decode(s).into_vec()?;
        Ok(PeerId::from_bytes(&bytes)?)
    }
}

pub type Enr = enr::Enr<enr::k256::ecdsa::SigningKey>;

pub enum MessageDomain {
    InvalidSnappy,
    ValidSnappy,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peer_id_serde() {
        let id_repr = "\"16Uiu2HAmVDji3ShrqL9DLnQo3teJcEWiKqy9qKefFFFxrz2EYwde\"";
        let id: PeerId = serde_json::from_str(id_repr).unwrap();
        let roundtrip_id_repr = serde_json::to_string(&id).unwrap();
        assert_eq!(id_repr, roundtrip_id_repr);
    }

    #[test]
    fn test_id_str_format() {
        let id_repr = "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N";
        let id: PeerId = PeerId::from_str(id_repr).unwrap();
        assert_eq!(format!("{id}"), "QmYyQSo1c1Ym7orWxLYvCrM2EmxFTANf8wXmmE7DWjhx5N")
    }
}

use k256::{ProjectivePoint, Scalar, Secp256k1, elliptic_curve::Curve};
use anyhow::Result;
use std::collections::BTreeMap;
use std::fmt::Display;
use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const G: ProjectivePoint = ProjectivePoint::GENERATOR;
pub const n: <Secp256k1 as Curve>::Uint = <Secp256k1 as Curve>::ORDER;
pub const infinity:ProjectivePoint = ProjectivePoint::IDENTITY;

pub(crate) fn point_add(A: ProjectivePoint, B:ProjectivePoint)-> ProjectivePoint {
    A + B
}

pub(crate) fn point_mul(A: ProjectivePoint, k: Scalar)-> ProjectivePoint {
    A * k
}

#[derive(PartialEq, Eq, Serialize, Clone, Copy, Deserialize, Default, Hash)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn new(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn to_vec(&self) -> Vec<u8> {
      self.0.to_vec()
  }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut s = String::new();
        let table = b"0123456789abcdef";
        for &b in self.0.iter() {
            s.push(table[(b >> 4) as usize] as char);
            s.push(table[(b & 0xf) as usize] as char);
        }
        s
    }

    pub fn display(&self) -> String {
        self.to_hex().chars().take(8).collect::<String>()
    }
}

impl Display for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

impl std::fmt::Debug for Digest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.display())
    }
}

impl From<[u8; 32]> for Digest {
    fn from(data: [u8; 32]) -> Self {
        Self::new(data)
    }
}

impl From<blake3::Hash> for Digest {
    fn from(value: blake3::Hash) -> Self {
        Digest::from(<[u8; 32]>::from(value))
    }
}

pub(crate) fn hash(data: &[u8]) -> Digest {
    let mut hasher = blake3::Hasher::new();
    hasher.update(data);
    let hash = hasher.finalize();
    Digest::from(<[u8; 32]>::from(hash))
}



#[cfg(test)]
mod tests{
    use super::*;

    #[test]
    fn test_point_operations(){
        let a = G;
        let b = G;
        let c = point_add(a,b);
        let d = point_mul(a, Scalar::from(2u64));
        assert_eq!(c,d);
    }
}

use crate::curve::n;
use core::iter::Product;
use k256::{Scalar, elliptic_curve::ff::Field, elliptic_curve::ff::PrimeField};
use rand_core::{RngCore, OsRng};
use std::collections::HashMap;

pub fn poly_eval(coeffs: &[Scalar], x: Scalar) -> Scalar {
    let mut y = Scalar::ZERO;
    for (i, c_i) in coeffs.iter().enumerate() {
        y = (y + c_i * &x.pow_vartime(&[i as u64, 0, 0, 0]));
    }
    y
}

pub fn modinv(x: Scalar) -> Scalar {
    x.invert().unwrap()
}

pub fn lagrange(T: &[Scalar], i: Scalar) -> Scalar {
    let mut lamb_i = Scalar::ONE;
    for &j in T {
        if j != i {
            lamb_i = (lamb_i * j);
            lamb_i = (lamb_i * modinv(j - i));
        }
    }
    lamb_i
}

pub fn split_secret(secret: Scalar, t: usize, k: usize) -> HashMap<u64,Scalar> {
    let mut coeffs = vec![secret];
    for _ in 0..(t - 1) {
        coeffs.push(Scalar::random(&mut OsRng));
    }

    let mut shares = HashMap::new();
    for i in 1..=k {
        let x = i as u64;
        shares.insert(x, poly_eval(&coeffs, Scalar::from(x as u64)));
    }

    shares
}

pub fn recover_secret(shares: HashMap<u64,Scalar>) -> Scalar {
    let t: Vec<Scalar> = shares.keys().cloned().map(Scalar::from).collect();
    let mut z = Scalar::ZERO;
    for (i, y) in shares {
        z += lagrange(&t, Scalar::from(i)) * y;
    }
    z
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::seq::SliceRandom;

    #[test]
    fn test_shamir() {
        for k in 3..10 {
            for t in 2..k {
                let secret = Scalar::random(&mut OsRng);
                let all_shares = split_secret(secret, t, k);
                let mut threshold_shares: HashMap<u64,Scalar> = all_shares
                    .clone()
                    .into_iter()
                    .collect::<Vec<(u64,Scalar)>>()
                    .choose_multiple(&mut rand::thread_rng(), t)
                    .cloned()
                    .collect();
                assert_eq!(recover_secret(threshold_shares), secret);
            }
        }
    }
}
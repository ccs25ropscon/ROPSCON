use std::collections::HashMap;
use k256::{ProjectivePoint, AffinePoint, Scalar, Secp256k1,
    elliptic_curve::ff::Field, elliptic_curve::ff::PrimeField,elliptic_curve::FieldBytes,
  elliptic_curve::group::GroupEncoding};
use rand_core::{RngCore, OsRng};
use k256::sha2::{Sha256,Digest};

use crate::curve::{G, n, infinity, point_add, point_mul};
use crate::shamir::{lagrange,split_secret};

pub fn u64_vec_to_scalar_vec(u64_vec: Vec<u64>) -> Vec<Scalar> {
  u64_vec.iter().map(|&num| Scalar::from(num)).collect()
}

#[derive(Clone, Debug)]
pub struct SessionContext {
    pub X: ProjectivePoint,
    pub i_to_X: HashMap<u64,ProjectivePoint>,
    pub msg: Vec<u8>,
    pub T: Vec<Scalar>,
    pub Tu64: Vec<u64>,
    pub R: ProjectivePoint,
    pub pre: (ProjectivePoint, ProjectivePoint),
    pub pre_i: (ProjectivePoint, ProjectivePoint),
}

pub fn pre_round() -> (Scalar, Scalar, ProjectivePoint, ProjectivePoint) {
    let mut rng = OsRng;
    let d_i = Scalar::random(&mut rng);
    let e_i = Scalar::random(&mut rng);
    let D_i = point_mul(G, d_i);
    let E_i = point_mul(G, e_i);
    (d_i, e_i, D_i, E_i)
}

pub fn pre_agg(i_to_pre: &HashMap<u64,(ProjectivePoint, ProjectivePoint)>, T: &[u64]) -> (ProjectivePoint, ProjectivePoint) {
    let mut D = infinity;
    let mut E = infinity;
    for &i in T {
        let (D_i, E_i) = i_to_pre[&i];
        D = point_add(D, D_i);
        E = point_add(E, E_i);
    }
    (D, E)
}

pub fn tagged_hash(tag: &str, msg: &[u8]) -> Vec<u8> {
  let mut tag_hash = Sha256::new();
  tag_hash.update(tag.as_bytes());
  let tag_hash = tag_hash.finalize();

  let mut hasher = Sha256::new();
  hasher.update(&tag_hash);
  hasher.update(&tag_hash);
  hasher.update(msg);
  hasher.finalize().to_vec()
}

pub fn H(tag: &str, items: &[&[u8]]) -> Scalar {
  let mut buf = Vec::new();
  for item in items {
      buf.extend_from_slice(item);
  }
  let field_bytes: FieldBytes<Secp256k1> = FieldBytes::<Secp256k1>::clone_from_slice(&tagged_hash(tag, &buf));
  Scalar::from_repr_vartime(field_bytes).unwrap()
}

pub fn share_val(ctx: &SessionContext, i: u64, s_i: Scalar) -> bool {
  let X = ctx.X;
  let X_i = ctx.i_to_X[&i];
  let msg = &ctx.msg;
  let T = &ctx.T;
  let R = ctx.R;
  let (D, E) = ctx.pre;
  let (D_i, E_i) = ctx.pre_i;

  let b = H("non", &[&X.to_bytes(), msg, &D.to_bytes(), &E.to_bytes()]);
  let c = H("sig", &[&X.to_bytes(), msg, &R.to_bytes()]);
  let lambda_i = lagrange(T, Scalar::from(i));
  let lhs = point_mul(G, s_i);
  let rhs = point_add(point_add(D_i, point_mul(E_i, b)), point_mul(X_i, (c * lambda_i).into()));
  lhs == rhs
}

pub fn sign_round(X: ProjectivePoint, msg: &[u8], T: &[Scalar], pre: (ProjectivePoint, ProjectivePoint), i: u64, sk_i: Scalar, spre_i: (Scalar, Scalar)) -> Scalar {
  let (D, E) = pre;
  let (d_i, e_i) = spre_i;
  let b = H("non", &[&X.to_bytes(), msg, &D.to_bytes(), &E.to_bytes()]);

  let R = point_add(D, point_mul(E, b));
  let c = H("sig", &[&X.to_bytes(), msg, &R.to_bytes()]);
  let lambda_i = lagrange(T, Scalar::from(i));
  (d_i + b * e_i + c * lambda_i * sk_i).into()
}

pub fn sign_agg(ctx: &SessionContext, i_to_s: &HashMap<u64, Scalar>) -> (ProjectivePoint, Scalar) {
  let X = ctx.X;
  let msg = &ctx.msg;
  let Tu64 = &ctx.Tu64;
  let R = ctx.R;

  let mut s = Scalar::ZERO;
  for &i in Tu64 {
      let s_i = i_to_s[&i];
      s += s_i;
  }
  (R, s)
}


pub fn verify(ctx: &SessionContext, sig: (ProjectivePoint, Scalar)) -> bool {
  let X = ctx.X;
  let msg = &ctx.msg;

  let (R, s) = sig;
  let c = H("sig", &[&X.to_bytes(), msg, &R.to_bytes()]);
  let lhs = point_mul(G, s);
  let rhs = point_add(R, point_mul(X, c));
  lhs == rhs
}

pub fn raw_verify(X:ProjectivePoint, msg:&[u8], sig: (ProjectivePoint, Scalar)) -> bool {
  //let X = ctx.X;
  //let msg = &ctx.msg;

  let (R, s) = sig;
  let c = H("sig", &[&X.to_bytes(), msg, &R.to_bytes()]);
  let lhs = point_mul(G, s);
  let rhs = point_add(R, point_mul(X, c));
  lhs == rhs
}

pub fn generate_keypair() -> (ProjectivePoint, Scalar) {
  let sk = Scalar::random(&mut OsRng);
  let X = point_mul(G, sk);
  (X,sk)
}

pub fn generate_keypairs(number: u64) -> (AffinePoint,Vec<(u64, AffinePoint, Scalar)>) {
  let sk = Scalar::random(&mut OsRng);
  let X = point_mul(G, sk);
  let k = number;
  let t = number - (number as f64 / 3.0).floor() as u64;
  let Tu64:Vec<u64> = (1..=number).collect();
  let i_to_sk = split_secret(sk, t as usize, k as usize);
  let mut i_to_X = HashMap::new();
  for &i in &Tu64 {
      i_to_X.insert(i, point_mul(G, i_to_sk[&i]));
  }
  let mut keypairs = Vec::with_capacity(number as usize);
  for i in 1..=number {
    let X_i = i_to_X[&i];
    let sk_i = i_to_sk[&i];
    keypairs.push((i, ProjectivePoint::to_affine(&X_i), sk_i));
  }

  (ProjectivePoint::to_affine(&X),keypairs)
}

pub fn generate_keypairs_projective(number: u64) -> Vec<(u64, ProjectivePoint, Scalar)> {
  let sk = Scalar::random(&mut OsRng);
  let X = point_mul(G, sk);
  let k = number;
  let t = number - (number as f64 / 3.0).floor() as u64;
  let Tu64:Vec<u64> = (1..=number).collect();
  let i_to_sk = split_secret(sk, t as usize, k as usize);
  let mut i_to_X = HashMap::new();
  for &i in &Tu64 {
      i_to_X.insert(i, point_mul(G, i_to_sk[&i]));
  }
  let mut keypairs = Vec::with_capacity(number as usize);
  for i in 1..=number {
    let X_i = i_to_X[&i];
    let sk_i = i_to_sk[&i];
    keypairs.push((i, X_i, sk_i));
  }

  keypairs
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pre_round() {
        let (d_i, e_i, D_i, E_i) = pre_round();
        //assert!(d_i.is_some());
        //assert!(e_i.is_some());
        assert_ne!(D_i, infinity);
        assert_ne!(E_i, infinity);
    }

    #[test]
    fn test_pre_agg() {
        let mut i_to_pre = HashMap::new();
        for i in 1..=3 {
            let (_, _, D_i, E_i) = pre_round();
            i_to_pre.insert(i, (D_i, E_i));
        }
        let T = vec![1, 2, 3];
        let (D, E) = pre_agg(&i_to_pre, &T);
        assert_ne!(D, infinity);
        assert_ne!(E, infinity);
    }

  #[test]
  fn test_sign_round_and_verify_2_of_3() {
    let msg = b"test message";
    let (X,sk) = generate_keypair();
    let Tu64 = vec![1, 2, 3];
    let T: Vec<Scalar> = u64_vec_to_scalar_vec(Tu64.clone());
    let t = 2;
    let k = 3;
    let i_to_sk = split_secret(sk, t, k);

    let mut i_to_pre = HashMap::new();
    let mut i_to_spre = HashMap::new();
    for &i in &Tu64 {
        let (d_i, e_i, D_i, E_i) = pre_round();
        i_to_pre.insert(i, (D_i, E_i));
        i_to_spre.insert(i, (d_i, e_i));
    }
    let (D, E) = pre_agg(&i_to_pre, &Tu64);
    let pre = (D, E);

    let mut i_to_s = HashMap::new();
    for &i in &Tu64 {
        let sk_i = i_to_sk[&i];
        let spre_i = i_to_spre[&i];
        let s_i = sign_round(X, msg, &T, pre, i, sk_i, spre_i);
        i_to_s.insert(i, s_i);
    }

    let mut i_to_X = HashMap::new();
    for &i in &Tu64 {
        i_to_X.insert(i, point_mul(G, i_to_sk[&i]));
    }

    let mut i_to_ctx = HashMap::new();
    for &i in &Tu64 {
      let ctx = SessionContext {
        X,
        i_to_X:i_to_X.clone(),
        msg: msg.to_vec(),
        T:T.clone(),
        Tu64:Tu64.clone(),
        R: point_add(D, point_mul(E, H("non", &[&X.to_bytes(), msg, &D.to_bytes(), &E.to_bytes()]))),
        pre,
        pre_i: i_to_pre[&i],
    };
      i_to_ctx.insert(i, ctx);
  }
    
    for &i in &Tu64 {
      assert!(share_val(&i_to_ctx[&i], i, i_to_s[&i]));
    }

    let i = 1;
    let sig = sign_agg(&i_to_ctx[&i], &i_to_s);
    assert!(verify(&i_to_ctx[&i], sig));
    // for comb in Tu64.iter().combinations(t as usize) {
    //     let mut i_to_s_subset = HashMap::new();
    //     for &i in comb {
    //         i_to_s_subset.insert(i, i_to_s[&i]);
    //     }
    //     let sig = sign_agg(&ctx, &i_to_s_subset);
    //     assert!(verify(&ctx, sig));
    // }
}

#[test]
fn test_generate_keypairs() {
    let number = 5;
    let keypairs = generate_keypairs_projective(number);

    assert_eq!(keypairs.len(), number as usize);

    for i in 1..=number {
        let (num, X, sk) = keypairs[(i - 1) as usize];
        assert_eq!(num, i);
        //assert_eq!(X, point_mul(G, split_secret(sk, (number - (number as f64 / 3.0).floor() as u64) as usize, number as usize)[&i]));
    }
}
}
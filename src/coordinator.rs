use std::collections::{HashMap, HashSet};
use k256::{ProjectivePoint, Scalar, Secp256k1,
  elliptic_curve::group::GroupEncoding};

use crate::curve::{point_add, point_mul};
use crate::tsalg::{H, SessionContext, pre_agg, sign_agg,u64_vec_to_scalar_vec};
use tracing::{trace};


#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum ActionType {
    NoOp = 1,
    Incoming = 3,
    SessionStart = 4,
    SessionSuccess = 2,
    NeedViewChange = 5,
}

#[derive(Clone)]
pub struct CoordinatorModel {
    X: ProjectivePoint,
    i_to_X: HashMap<u64, ProjectivePoint>,
    t: usize,
    n: usize,
    msg: Vec<u8>,
    ready: HashSet<u64>,
    malicious: HashSet<u64>,
    i_to_pre: HashMap<u64, (ProjectivePoint, ProjectivePoint)>,
    i_to_sid: HashMap<u64, u64>,
    i_to_ctx: HashMap<u64,SessionContext>,
    sid_ctr: u64,
    sid_to_Tu64: HashMap<u64, Vec<u64>>,
    sid_to_R: HashMap<u64, ProjectivePoint>,
    sid_to_pre: HashMap<u64, (ProjectivePoint, ProjectivePoint)>,
    sid_to_i_to_s: HashMap<u64, HashMap<u64, Scalar>>,
}

impl CoordinatorModel {
  pub fn new(X: ProjectivePoint, i_to_X: HashMap<u64, ProjectivePoint>, t: usize, n: usize, msg: Vec<u8>) -> Self {
      assert_eq!(i_to_X.len(), n);
      assert!((2 <= t && t <= n) || t==n);
      CoordinatorModel {
          X,
          i_to_X,
          t,
          n,
          msg,
          ready: HashSet::new(),
          malicious: HashSet::new(),
          i_to_pre: HashMap::new(),
          i_to_sid: HashMap::new(),
          i_to_ctx: HashMap::new(),
          sid_ctr: 0,
          sid_to_Tu64: HashMap::new(),
          sid_to_R: HashMap::new(),
          sid_to_pre: HashMap::new(),
          sid_to_i_to_s: HashMap::new(),
      }
  }
  pub fn handle_incoming(&mut self, i: u64, s_i: Option<Scalar>, pre_i: (ProjectivePoint, ProjectivePoint), share_is_valid: bool) -> (ActionType, 
    Option<Vec<(SessionContext,u64)>>, Option<(SessionContext, (ProjectivePoint, Scalar), u64)>) {
    if self.malicious.contains(&i) {
        return (ActionType::NoOp, None, None);
    }

    if self.ready.contains(&i) || (s_i.is_some() && !self.i_to_pre.contains_key(&i)) {
        let nvc = self.mark_malicious(i);
        if nvc == true {
          return (ActionType::NoOp, None, None);
        }else{
          return (ActionType::NeedViewChange, None, None);
        }
        // return (ActionType::NoOp, None, None);
    }

    if let Some(s_i) = s_i {
        if !share_is_valid {
            let nvc = self.mark_malicious(i);
            if nvc == true {
              return (ActionType::NoOp, None, None);
            }else{
              return (ActionType::NeedViewChange, None, None);
            }
            // return (ActionType::NoOp, None, None);
        }

        let sid = self.i_to_sid[&i];
        let Tu64 = &self.sid_to_Tu64[&sid];
        let ctx = SessionContext {
            X: self.X,
            i_to_X: self.i_to_X.clone(),
            msg: self.msg.clone(),
            T:Tu64.iter().map(|&i| Scalar::from(i)).collect(),
            Tu64:Tu64.iter().map(|&i| i as u64).collect(),
            R: self.sid_to_R[&sid],
            pre: self.sid_to_pre[&sid],
            pre_i: self.i_to_pre[&i],
        };
        self.sid_to_i_to_s.entry(sid).or_default().insert(i, s_i);

        if self.sid_to_i_to_s[&sid].len() == self.t {
            let sig = sign_agg(&ctx, &self.sid_to_i_to_s[&sid]);
            return (ActionType::SessionSuccess, None, Some((ctx, sig, sid)));
        }
    }

    self.i_to_pre.insert(i, pre_i);
    self.ready.insert(i);
    if self.ready.len() == self.t {
        self.sid_ctr += 1;
        let sid = self.sid_ctr;
        let Tu64:Vec<u64> = self.ready.clone().into_iter().collect();
        let T = u64_vec_to_scalar_vec(Tu64.clone());
        let pre = pre_agg(&self.i_to_pre, &Tu64);
        let (D, E) = pre;
        let b = H("non", &[&self.X.to_bytes(), &self.msg, &D.to_bytes(), &E.to_bytes()]);
        let R = point_add(D, point_mul(E, b));
        for &i in &Tu64 {
            self.i_to_sid.insert(i, sid);
        }
        self.sid_to_Tu64.insert(sid, Tu64.clone());
        self.sid_to_R.insert(sid, R);
        self.sid_to_pre.insert(sid, pre);
        self.ready.clear();

        let mut data = Vec::new();
        for &i in &Tu64 {
            let ctx = SessionContext {
                X: self.X,
                i_to_X: self.i_to_X.clone(),
                msg: self.msg.clone(),
                T: T.clone(),
                Tu64: Tu64.clone(),
                R,
                pre,
                pre_i: self.i_to_pre[&i],
            };
            data.push((ctx.clone(), i));
            self.i_to_ctx.insert(i,ctx);
        }
        return (ActionType::SessionStart, Some(data), None);
    }

    (ActionType::NoOp, None, None)
}


pub fn mark_malicious(&mut self, i: u64) -> bool {
  self.malicious.insert(i);
  trace!("mark:{} as malicious",i);
  if self.malicious.len() <= self.n - self.t{
    return true;
  }else{
    trace!("self.malicious.len() <= self.n - self.t");
    return false;
  }
}

pub fn set_msg(&mut self,msg:Vec<u8>){
  self.msg = msg;
}

pub fn set_ctx_i(&mut self,id:&u64, msg:Vec<u8>){
  if let Some(session_ctx) = self.i_to_ctx.get_mut(&id.clone()) {
    let sid = self.i_to_sid[id];
    let pre = self.sid_to_pre[&sid];
    let (D, E) = pre;
    let b = H("non", &[&self.X.to_bytes(), &msg, &D.to_bytes(), &E.to_bytes()]);
    let R = point_add(D, point_mul(E, b));
    self.sid_to_R.insert(sid, R);
    session_ctx.msg = msg;
    session_ctx.R = R;
  }
}

pub fn get_Tu64(&mut self)->Vec<u64>{
  let sid = self.sid_ctr;
  self.sid_to_Tu64[&sid].clone()
}

// pub fn get_pre(&mut self)->(ProjectivePoint, ProjectivePoint){
//   let sid = self.sid_ctr;
//   self.sid_to_Tu64[&sid]
// }

pub fn get_ctx(&mut self, id:u64)-> Option<SessionContext> {
  self.i_to_ctx.get(&id).cloned()
}

pub fn get_i_to_pre(&mut self, id:u64)-> (ProjectivePoint, ProjectivePoint){
  self.i_to_pre[&id].clone()
}

pub fn init_each_view(&mut self){
  self.msg = Vec::new();
  self.ready = HashSet::new();
  self.i_to_pre = HashMap::new();
  self.i_to_sid = HashMap::new();
  self.i_to_ctx = HashMap::new();
  self.sid_ctr = 0;
  self.sid_to_Tu64 = HashMap::new();
  self.sid_to_R = HashMap::new();
  self.sid_to_pre = HashMap::new();
  self.sid_to_i_to_s = HashMap::new();
}

pub fn init_each_viewchange(&mut self){
  self.malicious = HashSet::new();
}
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_core::{RngCore, OsRng};
    use crate::tsalg::*;
    use k256::{elliptic_curve::ff::Field, elliptic_curve::ff::PrimeField,elliptic_curve::FieldBytes};
    use crate::curve::{G, infinity, point_add, point_mul};
    use crate::shamir::{split_secret};

#[test]
fn test_coordinator_model() {
    let msg = b"test message";
    let sk = Scalar::random(&mut OsRng);
    let X = point_mul(G, sk);
    let Tu64 = vec![1, 2, 3];
    let T: Vec<Scalar> = u64_vec_to_scalar_vec(Tu64.clone());
    let t = 2;
    let n = 3;
    let i_to_sk = split_secret(sk, t, n);

    let mut i_to_pre = HashMap::new();
    let mut i_to_spre = HashMap::new();
    for &i in &Tu64 {
        let (d_i, e_i, D_i, E_i) = pre_round();
        i_to_pre.insert(i, (D_i, E_i));
        i_to_spre.insert(i, (d_i, e_i));
    }
    let (D, E) = pre_agg(&i_to_pre, &Tu64);
    let pre = (D, E);

    let mut i_to_X = HashMap::new();
    for &i in &Tu64 {
        i_to_X.insert(i, point_mul(G, i_to_sk[&i]));
    }

    let mut coordinator = CoordinatorModel::new(X, i_to_X.clone(), t, n, msg.to_vec());

    // Round 1: Participants send their pre-round values
    let i = 1;
    let (action_type, _, _) = coordinator.handle_incoming(i, None, i_to_pre[&i], true);
    assert_eq!(action_type, ActionType::NoOp);

    let i = 2;
    let (action_type, data, _) = coordinator.handle_incoming(i, None, i_to_pre[&i], true);
    assert_eq!(action_type, ActionType::SessionStart);
    // // Round 2: Coordinator starts a session and sends session data to participants
    let data = data.unwrap();
    assert_eq!(data.len(), t);

    let mut i_to_ctx = HashMap::new();
    for (ctx, i) in data {
        i_to_ctx.insert(i, ctx);
    }

    // Round 3: Participants send their signature shares
    let mut i_to_s = HashMap::new();
    for &i in &Tu64 {
        let ctx = &i_to_ctx[&i];
        let sk_i = i_to_sk[&i];
        let spre_i = i_to_spre[&i];
        let s_i = sign_round(ctx.X, &ctx.msg, &ctx.T, ctx.pre, i, sk_i, spre_i);
        i_to_s.insert(i, s_i);
        let share_is_valid = share_val(ctx, i, s_i);
        assert!(share_is_valid);


        let (action_type, _, result) = coordinator.handle_incoming(i, Some(s_i), i_to_pre[&i], share_is_valid);
        if i_to_s.len() < t {
            assert_eq!(action_type, ActionType::NoOp);
            assert!(result.is_none());
        } else {
            assert_eq!(action_type, ActionType::SessionSuccess);
            let (ctx, sig, _) = result.unwrap();
            assert!(verify(&ctx, sig));
            break;
        }
    }

    //Test handling invalid shares
    //let invalid_share = Scalar::random(&mut OsRng);
    //let (action_type, _, _) = coordinator.handle_incoming(1, Some(invalid_share), i_to_pre[&1], false);
    //assert_eq!(action_type, ActionType::NoOp);
    //assert!(coordinator.malicious.contains(&1));

    // Test handling duplicate pre-round values
    // let (action_type, _, _) = coordinator.handle_incoming(2, None, i_to_pre[&2], true);
    // assert_eq!(action_type, ActionType::NoOp);
    // assert!(coordinator.malicious.contains(&2));
}
}
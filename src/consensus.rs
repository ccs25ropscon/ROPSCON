use crate::{
    curve::Digest,
    data::{BlockType, Proof},
    nodeconf::NodeConfig,
    coordinator::{ActionType,CoordinatorModel},
};
use std::{
    collections::{BTreeMap, HashMap},
    slice::Iter,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use tokio::sync::{mpsc::Sender, Notify};

use serde::{Deserialize, Serialize};

use parking_lot::Mutex;
use tracing::{debug, trace, warn};

use crate::{
    data::{Block, BlockTree},
    network::MemoryNetworkAdaptor,
};

use k256::{ProjectivePoint, Scalar, AffinePoint};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) enum Message {
    Propose(Block, (AffinePoint, AffinePoint),Vec<Scalar>),
    // Vote(Digest, u64, Scalar),
    Vote(Digest, u64, Scalar, (AffinePoint, AffinePoint)),
    InitVote(Scalar, Scalar, AffinePoint, AffinePoint),
    // Contain the last vote of the sender, so that
    // it can tolerate more failures.
    // NewView(Proof, Digest, u64, (Scalar, Scalar, AffinePoint, AffinePoint)),
    NewView(Proof, (Scalar, Scalar, AffinePoint, AffinePoint)),
    NewNewView(Scalar),
}



impl Message {}

pub(crate) struct VoterState {
    pub id: u64,
    pub public_key: ProjectivePoint,
    pub view: u64,
    pub threshold: usize,
    pub topsig: Proof,
    pub commitsig: Proof,
    // <view, (what, whos)>
    pub votes: HashMap<u64, HashMap<Digest, Vec<u64>>>,
    pub notify: Arc<Notify>,
    pub best_view: Arc<AtomicU64>,
    // <view, (whos)>
    pub new_views: HashMap<u64, Vec<u64>>,
}

impl VoterState {
    pub fn new(id: u64, public_key: ProjectivePoint, view: u64, topsig: Proof, threshold: usize) -> Self {
        Self {
            id,
            public_key,
            view,
            threshold,
            topsig: topsig.to_owned(),
            commitsig: topsig,
            votes: HashMap::new(),
            notify: Arc::new(Notify::new()),
            best_view: Arc::new(AtomicU64::new(0)),
            new_views: HashMap::new(),
        }
    }

    pub(crate) fn view_add_one(&mut self) {
        // println!("{}: view add to {}", self.id, self.view + 1);
        // Prune old votes
        self.votes.retain(|v, _| v >= &self.view);
        self.new_views.retain(|v, _| v >= &self.view);


        self.view += 1;
        self.notify.notify_waiters();
    }

    pub(crate) fn add_new_view(&mut self, view: u64, who: u64) {
        let view_map = self.new_views.entry(view).or_default();
        // TODO, use a hashmap to collect messages.
        view_map.push(who);

        if view_map.len() == self.threshold {
            trace!(
                "{}: new view {} is ready, current: {}",
                self.id,
                view,
                self.view
            );
            self.best_view.store(view, Ordering::SeqCst);
            self.notify.notify_waiters();
        }
    }

    // return whether a new proof formed.
    // pub(crate) fn add_vote(
    //     &mut self,
    //     msg_view: u64,
    //     block_hash: Digest,
    //     voter_id: u64,
    // ) -> Option<Proof> {
    //     let view_map = self.votes.entry(msg_view).or_default();
    //     let voters = view_map.entry(block_hash).or_default();
    //     // TODO: check if voter_id is already in voters
    //     voters.push(voter_id);

    //     if voters.len() == self.threshold {
    //         trace!(
    //             "{}: Vote threshould {} is ready, current: {}",
    //             self.id,
    //             msg_view,
    //             self.view
    //         );
    //         Some(Proof::new(block_hash, msg_view))
    //     } else {
    //         trace!(
    //             "{}: Vote threshould {} is not ready, current: {}, threadhold: {}",
    //             self.id,
    //             msg_view,
    //             self.view,
    //             self.threshold
    //         );
    //         None
    //     }
    // }

    pub(crate) fn set_best_view(&mut self, view: u64) {
        self.best_view.store(view, Ordering::Relaxed);
    }

    pub(crate) fn best_view_ref(&self) -> Arc<AtomicU64> {
        self.best_view.to_owned()
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct NetworkPackage {
    pub(crate) from: u64,
    /// None means the message is a broadcast message.
    pub(crate) to: Option<u64>,
    /// None means the message is a global message.
    pub(crate) to_more: Option<Vec<u64>>,
    pub(crate) view: Option<u64>,
    pub(crate) message: Message,
    pub(crate) signature: u64,
}

pub struct Environment {
    pub(crate) block_tree: BlockTree,
    voter_set: VoterSet,
    network: MemoryNetworkAdaptor,
    pub(crate) finalized_block_tx: Option<Sender<(Block, BlockType, u64)>>,
}

impl Environment {
    pub(crate) fn new(
        block_tree: BlockTree,
        voter_set: VoterSet,
        network: MemoryNetworkAdaptor,
    ) -> Self {
        Self {
            block_tree,
            voter_set,
            network,
            finalized_block_tx: None,
        }
    }

    pub(crate) fn register_finalized_block_tx(&mut self, tx: Sender<(Block, BlockType, u64)>) {
        self.finalized_block_tx = Some(tx);
    }
}

pub(crate) struct Voter {
    id: u64,
    public_key: ProjectivePoint,
    config: NodeConfig,
    /// Only used when initialize ConsensusVoter.
    view: u64,
    env: Arc<Mutex<Environment>>,
}

#[derive(Debug, Clone)]
pub(crate) struct VoterSet {
    voters: Vec<u64>,
}

impl VoterSet {
    pub fn new(voters: Vec<u64>) -> Self {
        Self { voters }
    }

    pub fn threshold(&self) -> usize {
        self.voters.len() - (self.voters.len() as f64 / 3.0).floor() as usize
    }

    pub fn iter(&self) -> Iter<u64> {
        self.voters.iter()
    }
}

impl Iterator for VoterSet {
    type Item = u64;

    fn next(&mut self) -> Option<Self::Item> {
        self.voters.pop()
    }
}

impl Voter {
    pub(crate) fn new(id: u64, public_key:ProjectivePoint, config: NodeConfig, env: Arc<Mutex<Environment>>) -> Self {
        let view = 1;
        Self {
            id,
            public_key,
            config,
            view,
            env,
        }
    }

    pub(crate) async fn start(&mut self) {
        // Start from view 0, and keep increasing the view number
        let topsig = self.env.lock().block_tree.genesis().0.justify.clone();
        let voters = self.env.lock().voter_set.to_owned();
        let n = voters.voters.len();
        let t = n - (n as f64 / 3.0).floor() as usize;
        let state = Arc::new(Mutex::new(VoterState::new(
            self.id,
            self.public_key,
            self.view,
            topsig,
            voters.threshold(),
        )));
        let notify = state.lock().best_view_ref();
        let leadership = Arc::new(Mutex::new(Leadership::new(voters, self.config.get_node_settings().leader_rotation)));
        let coordinatorship = Arc::new(Mutex::new(CoordinatorModel::new(self.config.get_mpk(), self.config.get_i_to_X_projective(), t, n, Vec::new())));

        let voter = ConsensusVoter::new(
            self.config.to_owned(),
            leadership.to_owned(),
            coordinatorship.to_owned(),
            state.to_owned(),
            self.env.to_owned(),
            notify.to_owned(),
        );
        let leader = voter.clone();
        let pacemaker = voter.clone();

        let handler1 = tokio::spawn(async {
            leader.run_as_leader().await;
        });

        let handler2 = tokio::spawn(async {
            voter.run_as_voter().await;
        });

        let handler3 = tokio::spawn(async {
            pacemaker.run_as_pacemaker().await;
        });

        let (r1, r2, r3) = tokio::join!(handler1, handler2, handler3);
        // TODO: handle error
        r1.unwrap();
        r2.unwrap();
        r3.unwrap();
    }
}

#[derive(Clone)]
struct ConsensusVoter {
    config: NodeConfig,
    leadership: Arc<Mutex<Leadership>>,
    coordinatorship: Arc<Mutex<CoordinatorModel>>,
    state: Arc<Mutex<VoterState>>,
    env: Arc<Mutex<Environment>>,
    collect_view: Arc<AtomicU64>,
}

#[derive(Clone)]
struct Leadership {
    voters: VoterSet,
    leader_rotation: usize,
    trigger: usize,
    proposed_block: Block,
}

impl Leadership {
    fn new(voters: VoterSet, leader_rotation: usize) -> Self {
        Self {
            voters,
            leader_rotation,
            trigger: 0,
            proposed_block: Block::genesis(),
        }
    }

    fn get_leader(&self, view: u64) -> u64 {
        self.voters
            .voters
            .get(((view / self.leader_rotation as u64) % self.voters.voters.len() as u64) as usize)
            .unwrap()
            .to_owned()
    }
}

impl ConsensusVoter {
    fn new(
        config: NodeConfig,
        leadership: Arc<Mutex<Leadership>>,
        coordinatorship: Arc<Mutex<CoordinatorModel>>,
        state: Arc<Mutex<VoterState>>,
        env: Arc<Mutex<Environment>>,
        collect_view: Arc<AtomicU64>,
    ) -> Self {
        Self {
            config,
            state,
            env,
            collect_view,
            leadership,
            coordinatorship,
        }
    }

    // fn get_leader(view: u64, voters: &VoterSet, leader_rotation: usize) -> PublicKey {
    //     voters
    //         .voters
    //         .get(((view / leader_rotation as u64) % voters.voters.len() as u64) as usize)
    //         .unwrap()
    //         .to_owned()
    // }


    fn package_message(
        id: u64,
        message: Message,
        view: u64,
        to: Option<u64>,
        to_more: Option<Vec<u64>>,
    ) -> NetworkPackage {
        NetworkPackage {
            from: id,
            to,
            to_more,
            view: Some(view),
            message,
            signature: 0,
        }
    }

    fn new_key_block(
        env: Arc<Mutex<Environment>>,
        view: u64,
        topsig: Proof,
        (affinePoint1,affinePoint2): (AffinePoint, AffinePoint),
        T: Vec<Scalar>,
        id: u64,
        to: Option<u64>,
        to_more: Option<Vec<u64>>
    ) -> NetworkPackage {
        let block = env.lock().block_tree.new_key_block(topsig);
        Self::package_message(id, Message::Propose(block,(affinePoint1,affinePoint2),T), view, to, to_more)
    }

        fn create_key_block(
        env: Arc<Mutex<Environment>>,
        topsig: Proof,
    ) -> Block {
        let block = env.lock().block_tree.new_key_block(topsig);
        block
    }

        fn package_key_block(
        view: u64,
        block:Block,
        (affinePoint1,affinePoint2): (AffinePoint, AffinePoint),
        T: Vec<Scalar>,
        id: u64,
        to: Option<u64>,
        to_more: Option<Vec<u64>>
    ) -> NetworkPackage {
        Self::package_message(id, Message::Propose(block,(affinePoint1,affinePoint2),T), view, to, to_more)
    }


    fn update_sig_high(&self, new_sig: Proof) -> bool {
        let mut state = self.state.lock();
        // debug!("new_sig in: {}, topsig in: {}",new_sig.view,state.topsig.view);
        if new_sig.view > state.topsig.view {
            debug!(
                "Node {} update highest proof from {:?} to {:?}",
                self.config.get_id(),
                state.topsig,
                new_sig
            );
            state.topsig = new_sig.to_owned();
            drop(state);
            self.env
                .lock()
                .block_tree
                .switch_latest_key_block(new_sig.node);
            true
        } else {
            false
        }
    }

    async fn process_message(
        &mut self,
        pkg: NetworkPackage,
        id: u64,
        voted_view: &mut u64,
        tx: &Sender<NetworkPackage>,
        finalized_block_tx: &Option<Sender<(Block, BlockType, u64)>>,
    ) {
        let view = pkg.view.unwrap();
        let message = pkg.message;
        let from = pkg.from;
        //let to_more = pkg.to_more;
        let current_view = self.state.lock().view;
        match message {
          Message::InitVote(scalar1, scalar2, affinePoint1, affinePoint2)=>{
            trace!("{}: Handle initvote incoming, from:{}",id, from);
            let (action_type, data, _) = self.coordinatorship.lock().handle_incoming(from, None, (ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2)), true);
            if action_type == ActionType::SessionStart{
              let data = data.unwrap();
    
              let mut i_to_ctx = HashMap::new();
              let mut Tu64 = Vec::new();
              let mut T = Vec::new();
              let mut projectivePoint1 = ProjectivePoint::IDENTITY;
              let mut projectivePoint2 = ProjectivePoint::IDENTITY;
              let topsig = self.state.lock().topsig.clone();
              let mut block = self.leadership.lock().proposed_block.clone();
              let mut hash = block.hash();
              let trigger = self.leadership.lock().trigger.clone();
              if trigger == 0{
                block = Self::create_key_block(self.env.to_owned(), topsig);
                self.leadership.lock().proposed_block = block.clone();
                trace!("{}:create key block",id);
                hash = block.hash();
                self.leadership.lock().trigger = 1;
                //trace!("{}: trigger 0 -> 1",id);
              }

              let mut ilast = 0;
              for (ctx, i) in data {
                  i_to_ctx.insert(i, ctx);
                  ilast = i;
                  //trace!("ctx before:{:#?}", self.coordinatorship.get_ctx(i));
                  self.coordinatorship.lock().set_ctx_i(&i,hash.to_vec());
                  //trace!("ctx after:{:#?}", self.coordinatorship.get_ctx(i));
                  
              }
              Tu64 = i_to_ctx[&ilast].Tu64.clone();
              T = i_to_ctx[&ilast].T.clone();
              (projectivePoint1,projectivePoint2)=i_to_ctx[&ilast].pre.clone();
              let affinePoint1 = ProjectivePoint::to_affine(&projectivePoint1);
              let affinePoint2 = ProjectivePoint::to_affine(&projectivePoint2);
              // onPropose
              // let topsig = self.state.lock().topsig.clone();
              // let pkg = Self::new_key_block(self.env.to_owned(), view, topsig, (affinePoint1,affinePoint2), T, id, None, Some(Tu64));
              // let pkg = Self::package_key_block(view, block, (affinePoint1,affinePoint2), T, id, None, Some(Tu64.clone()));
              let pkg = Self::package_key_block(view, block.clone(), (affinePoint1,affinePoint2), T, id, None, None);
              tracing::trace!("{}: leader propose block (or broadcast block in the signing phase) in view: {}, block:{:?}", id, view, block);
              tx.send(pkg).await.unwrap();              

            }else if action_type == ActionType::NeedViewChange{
              let hash = self.leadership.lock().proposed_block.hash().clone();
              let scalar1 = self.config.single_sign(hash);
              let pkg = 
                Self::package_message(
                id,
                Message::NewNewView(scalar1),
                view,
                None,
                None,
            );
            tx.send(pkg).await.unwrap();  
            self.coordinatorship.lock().init_each_viewchange();
            }
          },
            Message::Propose(block,(affinePoint1,affinePoint2),T) => {
                if view < self.state.lock().view {
                    return;
                }
                let hash = block.hash();

                // Verify the validity of the block
                let b_x = block.justify.node;
                let sig = block.justify.sig;
                if let Some(sig) = sig {
                  let validity = self.config.verify(b_x,sig);
                  // trace!("Validaty: {}",validity);
                  if validity == false{
                    return;
                  }
                }else if b_x == Digest::default(){
                  //trace!("Genesis Block");
                }else{
                  return;
                }
                

                let block_justify = block.justify.clone();
                let block_hash = block.hash();

                if from != id {
                    self.env.lock().block_tree.add_block(block.clone(), BlockType::Key);
                    //trace!("{}: add block_hash:{:?}, block:{:?}, tree:{:?}",id, block.hash(), block ,self.env.lock().block_tree.blocks);
                }

                // onReceiveProposal
                if let Some(pkg) = {
                    let commitsig = self.state.lock().commitsig.clone();
                    let safety = self
                        .env
                        .lock()
                        .block_tree
                        .extends(commitsig.node, block_hash);
                    let liveness = block_justify.view >= commitsig.view;

                    if view > *voted_view && (safety || liveness) {
                        *voted_view = view;

                        // Suppose the block is valid, vote for it
                        if T.contains(&Scalar::from(id.clone())) {
                            let (affinePoint3, affinePoint4) = self.config.get_pre();
                            Some(Self::package_message(
                            id,
                            Message::Vote(hash, id, self.config.sign(hash,&T,(ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2))),(affinePoint3, affinePoint4)),
                            //Message::Vote(hash, id, self.config.sign_test(Vec::new(),&T,(ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2)))),
                            current_view,
                            Some(self.leadership.lock().get_leader(current_view)),
                            None,
                        ))
                        }else{
                          None
                        }
                        // Some(Self::package_message(
                        //     id,
                        //     Message::Vote(hash, id, self.config.sign(hash,&T,(ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2)))),
                        //     //Message::Vote(hash, id, self.config.sign_test(Vec::new(),&T,(ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2)))),
                        //     current_view,
                        //     Some(self.leadership.get_leader(current_view)),
                        //     None,
                        // ))
                    } else {
                        trace!(
                            "{}: Safety: {} or Liveness: {} are both invalid",
                            id,
                            safety,
                            liveness
                        );
                        None
                    }
                } {
                    trace!("{}: send vote {:?} for block: {:?}", id, pkg, hash.as_bytes());
                    tx.send(pkg).await.unwrap();
                }

                // update
                let b_y = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_x)
                    .unwrap()
                    .0
                    .justify
                    .node;
                let b_z = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_y)
                    .unwrap()
                    .0
                    .justify
                    .node;

                trace!("{}: enter PRE-COMMIT phase", id);
                // PRE-COMMIT phase on b_x
                let succes = self.update_sig_high(block_justify);

                let larger_view = self
                    .env
                    .lock()
                    .block_tree
                    .get_block(b_x)
                    .unwrap()
                    .0
                    .justify
                    .view
                    > self.state.lock().commitsig.view;
                if larger_view {
                    trace!("{}: enter COMMIT phase", id);
                    // COMMIT phase on b_y
                    self.state.lock().commitsig = self
                        .env
                        .lock()
                        .block_tree
                        .get_block(b_x)
                        .unwrap()
                        .0
                        .justify
                        .clone();
                }
                // trace!("{:?} {:?} {:?}: bx, by, bz", b_x, b_y, b_z);
                let is_parent = self.env.lock().block_tree.is_parent(b_y, b_x);
                if is_parent {
                    let is_parent = self.env.lock().block_tree.is_parent(b_z, b_y);
                    if is_parent {
                        trace!("{}: enter DECIDE phase", id);
                        // DECIDE phase on b_z / Finalize b_z
                        let finalized_blocks = self.env.lock().block_tree.finalize(b_z);
                        // onCommit
                        if let Some(tx) = finalized_block_tx.as_ref() {
                            for block in finalized_blocks {
                                tx.send(block).await.unwrap();
                            }
                        }
                    }
                }

                trace!("{}: view add one", id);
                // Finish the view
                let oview = self.state.lock().view;
                let oleader = self.leadership.lock().get_leader(oview);
                self.state.lock().view_add_one();
                let nview = self.state.lock().view;
                let nleader = self.leadership.lock().get_leader(nview);
                if nleader == id && oleader!=id {
                  self.leadership.lock().trigger = 0;
                  self.coordinatorship.lock().init_each_view();
                }else if nleader == id && oleader == id{
                  self.leadership.lock().trigger = 0;
                }
                let (scalar1,scalar2) = self.config.get_spre();
                let (affinePoint1, affinePoint2) = self.config.get_pre();
                let next_view_leader = self.leadership.lock().get_leader(nview);
                if let Some(pkg) = {
                      Some(Self::package_message(
                          id,
                          Message::InitVote(scalar1, scalar2, affinePoint1, affinePoint2),
                          nview,
                          Some(next_view_leader),
                          None,
                      ))
                  }
              {
                  trace!("{}: send init vote {:?} for block", id, pkg);
                  tx.send(pkg).await.unwrap();
              }

                tracing::trace!("{}: voter finish view: {}", id, current_view);
            }
            Message::Vote(block_hash, author, signature, (affinePoint1, affinePoint2)) => {
                // onReceiveVote
                let mut proof = None;
                let ctx = match self.coordinatorship.lock().get_ctx(author) {
                  Some(ctx) => ctx,
                  None => return,
                };
                // let i_to_pre = self.coordinatorship.lock().get_i_to_pre(author);
                let i_to_pre = (ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2));
                let share_is_valid = self.config.share_val(&ctx, author, signature);
                // if share_is_valid {
                //   proof = self.state.lock().add_vote(view, block_hash, from);
                // }
                //trace!("ctx is: {:?}",ctx);
                trace!("{}: Handle vote incoming, is valid:{}",id, share_is_valid);
                let (action_type, _, result) = self.coordinatorship.lock().handle_incoming(from, Some(signature), i_to_pre, share_is_valid);
                if action_type == ActionType::NeedViewChange{
                  let hash = self.leadership.lock().proposed_block.hash().clone();
                  let scalar1 = self.config.single_sign(hash);
                  let pkg = 
                    Self::package_message(
                    id,
                    Message::NewNewView(scalar1),
                    view,
                    None,
                    None,
                );
                tx.send(pkg).await.unwrap();  
                self.coordinatorship.lock().init_each_viewchange();
                return;
              }
                else if action_type != ActionType::SessionSuccess {
                  trace!(
                    "{}: (ROPSCON) Vote threshold {} is not ready, current: {}",
                    id,
                    view,
                    current_view,
                );
              } else {
                  //assert_eq!(action_type, ActionType::SessionSuccess);
                  let (ctx, sig, _) = result.unwrap();
                  let (R,s) = sig;
                  proof = Some(Proof::new(block_hash, view, Some((ProjectivePoint::to_affine(&R),s))));
                  self.coordinatorship.lock().init_each_view();
                  trace!(
                    "{}: (ROPSCON) Vote threshold {} is ready, current: {}",
                    id,
                    view,
                    current_view,
                );
                  //assert!(verify(&ctx, sig));
                  //break;
              }

                if let Some(proof) = proof {
                    self.update_sig_high(proof);
                    self.state.lock().set_best_view(view);
                }
            }
            Message::NewView(high_sig, (scalar1, scalar2, affinePoint1, affinePoint2)) => {
                // trace!("{}: self trigger is: {}",id, self.leadership.lock().trigger);
                let b_x = high_sig.node.clone();
                let sig = high_sig.sig.clone();
                if let Some(sig) = sig {
                  let validity = self.config.verify(b_x,sig);
                  // trace!("Validaty: {}",validity);
                  if validity == false{
                    return;
                  }
                }else if b_x == Digest::default(){
                  //trace!("Genesis Block");
                }else{
                  return;
                }
                self.update_sig_high(high_sig);

                //author.verify(&digest, &signature).unwrap();

                // let proof = self.state.lock().add_vote(view, digest, from);

                // if let Some(proof) = proof {
                //     self.update_sig_high(proof);
                //     self.state.lock().set_best_view(view);
                // }

                self.state.lock().add_new_view(view, from);
                trace!("{}: (Newview) Handle initvote incoming, from:{}",id, from);
                let (action_type, data, _) = self.coordinatorship.lock().handle_incoming(from, None, (ProjectivePoint::from(affinePoint1), ProjectivePoint::from(affinePoint2)), true);
                if action_type == ActionType::SessionStart{
                  let data = data.unwrap();
        
                  let mut i_to_ctx = HashMap::new();
                  let mut Tu64 = Vec::new();
                  let mut T = Vec::new();
                  let mut projectivePoint1 = ProjectivePoint::IDENTITY;
                  let mut projectivePoint2 = ProjectivePoint::IDENTITY;
                  let topsig = self.state.lock().topsig.clone();
                  let mut block = self.leadership.lock().proposed_block.clone();
                  let mut hash = block.hash();
                  let trigger = self.leadership.lock().trigger.clone();
                  if trigger == 0 {
                    block = Self::create_key_block(self.env.to_owned(), topsig);
                    self.leadership.lock().proposed_block = block.clone();
                    trace!("{}:create key block",id);
                    hash = block.hash();
                    self.leadership.lock().trigger = 1;
                    //trace!("{}: trigger 0 -> 1",id);
                  }
    
                  let mut ilast = 0;
                  for (ctx, i) in data {
                      i_to_ctx.insert(i, ctx);
                      ilast = i;
                      //trace!("ctx before:{:#?}", self.coordinatorship.get_ctx(i));
                      self.coordinatorship.lock().set_ctx_i(&i,hash.to_vec());
                      //trace!("ctx after:{:#?}", self.coordinatorship.get_ctx(i));
                      
                  }
                  Tu64 = i_to_ctx[&ilast].Tu64.clone();
                  T = i_to_ctx[&ilast].T.clone();
                  (projectivePoint1,projectivePoint2)=i_to_ctx[&ilast].pre.clone();
                  let affinePoint1 = ProjectivePoint::to_affine(&projectivePoint1);
                  let affinePoint2 = ProjectivePoint::to_affine(&projectivePoint2);
                  // onPropose
                  // let topsig = self.state.lock().topsig.clone();
                  // let pkg = Self::new_key_block(self.env.to_owned(), view, topsig, (affinePoint1,affinePoint2), T, id, None, Some(Tu64));
                  // let pkg = Self::package_key_block(view, block, (affinePoint1,affinePoint2), T, id, None, Some(Tu64.clone()));
                  let pkg = Self::package_key_block(view, block.clone(), (affinePoint1,affinePoint2), T, id, None, None);
                  tracing::trace!("{}: leader propose block in view: {}, block:{:?}", id, view, block);
                  tx.send(pkg).await.unwrap();              
    
                }
            }
            Message::NewNewView(scalar1) => {
                if !self.config.single_verify(scalar1){
                  return;
                }
                trace!("leader actively triggers view changing in view {}",view);
                let oview = self.state.lock().view;
                let oleader = self.leadership.lock().get_leader(oview);
                if oleader == from {
                  self.state.lock().view_add_one();
                }
                let nview = self.state.lock().view;
                let nleader = self.leadership.lock().get_leader(nview);
                if oview!=nview && nleader == id && oleader!=id {
                  self.leadership.lock().trigger = 0;
                  self.coordinatorship.lock().init_each_view();
                }else if oview!=nview && nleader == id && oleader == id{
                  self.leadership.lock().trigger = 0;
                }
                let (scalar1,scalar2) = self.config.get_spre();
                let (affinePoint1, affinePoint2) = self.config.get_pre();
                let next_view_leader = self.leadership.lock().get_leader(nview);
                if let Some(pkg) = {
                      Some(Self::package_message(
                          id,
                          Message::InitVote(scalar1, scalar2, affinePoint1, affinePoint2),
                          nview,
                          Some(next_view_leader),
                          None,
                      ))
                  }
              {
                  trace!("{}: send init vote {:?} for block", id, pkg);
                  tx.send(pkg).await.unwrap();
              }
            }
        }
    }

    async fn run_as_voter(mut self) {
        let id = self.state.lock().id;
        let finalized_block_tx = self.env.lock().finalized_block_tx.to_owned();
        let (mut rx, tx) = {
            let mut env = self.env.lock();
            let rx = env.network.take_receiver();
            let tx = env.network.get_sender();
            (rx, tx)
        };
        let mut buffer: BTreeMap<u64, Vec<NetworkPackage>> = BTreeMap::new();

        // The view voted for last block.
        //
        // Initialize as 0, since we voted for genesis block.
        let mut voted_view = 0;
        let (scalar1,scalar2) = self.config.get_spre();
        let (affinePoint1, affinePoint2) = self.config.get_pre();
        let next_view_leader = self.leadership.lock().get_leader(voted_view + 1);
        if let Some(pkg) = {
              Some(Self::package_message(
                  id,
                  Message::InitVote(scalar1, scalar2, affinePoint1, affinePoint2),
                  voted_view + 1,
                  Some(next_view_leader),
                  None,
              ))
          }
      {
          trace!("{}: send init vote {:?} for block", id, pkg);
          tx.send(pkg).await.unwrap();
      }


        while let Some(pkg) = rx.recv().await {
            let view = pkg.view.unwrap();
            let current_view = self.state.lock().view;

            if !buffer.is_empty() {
                while let Some((&view, _)) = buffer.first_key_value() {
                    if view < current_view - 1 {
                        // Stale view
                        buffer.pop_first();
                        trace!("{}: stale view: {}", id, view);
                    } else if view > current_view {
                        break;
                    } else {
                        // It's time to process the pkg.
                        let pkgs: Vec<NetworkPackage> = buffer.pop_first().unwrap().1;
                        trace!(
                            "{}: process buffered (view: {}, current_view: {}) pkgs: {}",
                            id,
                            view,
                            current_view,
                            pkgs.len()
                        );
                        for pkg in pkgs.into_iter() {
                            self.process_message(
                                pkg,
                                id,
                                &mut voted_view,
                                &tx,
                                &finalized_block_tx,
                            )
                            .await;
                        }
                    }
                }
            }

            let current_view = self.state.lock().view;

            if view < current_view - 1 {
                // Stale view, drop it.
                continue;
            } else if view > current_view {
                // Received a message from future view, buffer it.
                trace!(
                    "{}: future (view: {}, current_view: {}) buffer pkg: {:?}",
                    id,
                    view,
                    current_view,
                    pkg
                );
                if let Some(v) = buffer.get_mut(&view) {
                    v.push(pkg);
                } else {
                    buffer.insert(view, vec![pkg]);
                }
            } else {
                // Deal with the messages larger than current view
                self.process_message(pkg, id, &mut voted_view, &tx, &finalized_block_tx)
                    .await;
            }
        }
    }

    async fn run_as_leader(mut self) {
        let id = self.state.lock().id;
        let batch_size = self.config.get_node_settings().batch_size;

        // println!("{}: leader start", id);

        loop {
            let tx = self.env.lock().network.get_sender();
            let view = self.state.lock().view;
            let curleader = self.leadership.lock().get_leader(view).clone();
            if curleader == id {
                //self.coordinatorship.init_each_view();
                tracing::trace!("{}: start as leader in view: {}", id, view);
 
                let topsig = { self.state.lock().topsig.to_owned() };

                while self.collect_view.load(Ordering::SeqCst) + 1 < view {
                    tokio::task::yield_now().await;
                }

                // // onPropose
                // let topsig = self.state.lock().topsig.clone();
                // let pkg = Self::new_key_block(self.env.to_owned(), view, topsig, id);
                // tracing::trace!("{}: leader propose block in view: {}", id, view);
                // tx.send(pkg).await.unwrap();
            }

            let notify = self.state.lock().notify.clone();
            // Get awoke if the view is changed.
            notify.notified().await;
            {
                let view = self.state.lock().view;
                trace!(
                    "{}: leader notified, view: {}, leader: {}",
                    id,
                    view,
                    self.leadership.lock().get_leader(view)
                );
            }
        }
    }

    async fn run_as_pacemaker(mut self) {
        let timeout =
            tokio::time::Duration::from_millis(self.config.get_node_settings().timeout as u64);
        let tx = self.env.lock().network.get_sender();
        let id = self.config.get_id();

        let mut multiplexer = 1;

        loop {
            let past_view = self.state.lock().view;
            let next_awake = tokio::time::Instant::now() + timeout.mul_f64(multiplexer as f64);
            trace!("{}: pacemaker start", id);
            tokio::time::sleep_until(next_awake).await;
            trace!("{}: pacemaker awake", id);

            // If last vote is received later then 1s ago, then continue to sleep.
            let current_view = self.state.lock().view;
            if current_view != past_view {
                multiplexer = 1;
                continue;
            }

            warn!(
                "{} timeout!!! in view {}, leader: {}",
                id,
                current_view,
                self.leadership.lock().get_leader(current_view)
            );

            // otherwise, try send a new-view message to nextleader
            let (next_leader, next_leader_view) = self.get_next_leader();
            trace!("{} send new_view to {}", id, next_leader);
            let pkg = self.new_new_view(next_leader_view, next_leader);
            tx.send(pkg).await.unwrap();

            self.state.lock().view = next_leader_view;
            multiplexer += 1;
            trace!("(NewView) {}: self trigger is: {}",id, self.leadership.lock().trigger);
        }
    }

    // fn new_new_view(&self, view: u64, next_leader: u64) -> NetworkPackage {
    //     // latest Vote
    //     let digest = self.env.lock().block_tree.latest;
    //     let id = self.config.get_id();
    //     let signature = self.config.get_private_key().sign(&digest);
    //     let new_view =
    //         Message::NewView(self.state.lock().topsig.clone(), digest, id, signature);
    //     Self::package_message(self.state.lock().id, new_view, view, Some(next_leader),None)
    // }
    fn new_new_view(&mut self, view: u64, next_leader: u64) -> NetworkPackage {
      // latest Vote
      // let digest = self.env.lock().block_tree.latest;
      // let id = self.config.get_id();
      // // todo: set signature
      // //let signature = self.config.get_private_key().sign(&digest);
      // let signature = Scalar::ZERO;
      // let new_view =
      //     Message::NewView(self.state.lock().topsig.clone(), digest, id, signature);
      // Self::package_message(self.state.lock().id, new_view, view, Some(next_leader),None)
      // todo: set signature
      //let signature = self.config.get_private_key().sign(&digest);
      let id = self.config.get_id();
      if next_leader == id {
        self.leadership.lock().trigger = 0;
        //trace!("(NewView) {}: self trigger is: {}",id, self.leadership.trigger);;
        self.coordinatorship.lock().init_each_view();
      }
      let (scalar1,scalar2) = self.config.get_spre();
      let (affinePoint1, affinePoint2) = self.config.get_pre();
      let pkg = 
                Self::package_message(
                id,
                Message::NewView(self.state.lock().topsig.clone(), (scalar1, scalar2, affinePoint1, affinePoint2)),
                view,
                Some(self.leadership.lock().get_leader(view)),
                None,
            );
        pkg
  }

    // -> (leaderId, view)
    fn get_next_leader(&self) -> (u64, u64) {
        let mut view = self.state.lock().view;
        let current_leader = self.leadership.lock().get_leader(view);
        loop {
            view += 1;
            let next_leader = self.leadership.lock().get_leader(view);
            if next_leader != current_leader {
                return (next_leader, view);
            }
        }
    }
}

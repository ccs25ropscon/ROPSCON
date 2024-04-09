use anyhow::Result;
use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Write,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize,Serializer, Deserializer};
use thiserror::Error;
use k256::{ProjectivePoint, Scalar, AffinePoint,elliptic_curve::group::GroupEncoding};
use crate::tsalg::{pre_round,sign_round, share_val, SessionContext, raw_verify, H};
// use serde::de::{self, Visitor};
// use core::fmt;
// use core::marker::PhantomData;

use crate::{
    cli::Cli,
    consensus::VoterSet,
    curve::Digest,
    tsalg::{generate_keypair},
};


// // 实现 Serialize
// impl Serialize for ProjectivePoint {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: Serializer,
//     {
//         // 将 ProjectivePoint 转换为 AffinePoint 并序列化
//         let affine: AffinePoint = self.to_affine();
//         affine.serialize(serializer)
//     }
// }

// // 创建 Visitor 以协助反序列化
// struct ProjectivePointVisitor {
//     marker: PhantomData<fn() -> ProjectivePoint>,
// }

// impl ProjectivePointVisitor {
//     fn new() -> Self {
//         ProjectivePointVisitor {
//             marker: PhantomData,
//         }
//     }
// }

// // 实现 Visitor
// impl<'de> Visitor<'de> for ProjectivePointVisitor {
//     type Value = ProjectivePoint;

//     fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
//         formatter.write_str("a valid ProjectivePoint")
//     }

//     fn visit_seq<V>(self, mut seq: V) -> Result<ProjectivePoint, V::Error>
//     where
//         V: de::SeqAccess<'de>,
//     {
//         // 反序列化为 AffinePoint
//         let affine: AffinePoint = Deserialize::deserialize(de::value::SeqAccessDeserializer::new(&mut seq))?;
//         // 转换为 ProjectivePoint
//         Ok(ProjectivePoint::from(affine))
//     }
// }

// // 实现 Deserialize
// impl<'de> Deserialize<'de> for ProjectivePoint {
//     fn deserialize<D>(deserializer: D) -> Result<ProjectivePoint, D::Error>
//     where
//         D: Deserializer<'de>,
//     {
//         deserializer.deserialize_seq(ProjectivePointVisitor::new())
//     }
// }

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("Failed to parse config file: {0}")]
    ParseError(#[from] config::ConfigError),

    #[error("Wrong local_addr")]
    LocalAddrError,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct NodeSettings {
    pub(crate) transaction_size: usize,
    pub(crate) batch_size: usize,
    /// The maximum number of transactions in the mempool.
    ///
    /// For best performance, this should be a multiple of batch_size.
    pub(crate) mempool_size: usize,
    pub(crate) pretend_crash: bool,
    pub(crate) pretend_malicious: bool,
    /// Rotate leadership every `rotate_every` key blocks.
    pub(crate) leader_rotation: usize,
    /// The number of blocks to keep in the ledger.
    pub(crate) gc_depth: usize,
    /// Pacemaker timeout
    pub(crate) timeout: usize,
}

impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            transaction_size: 128,
            batch_size: 500,
            mempool_size: 5000,
            pretend_crash: false,
            pretend_malicious: false,
            leader_rotation: 1,
            gc_depth: 2000,
            timeout: 20000,
        }
    }
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub(crate) struct ClientConfig {
    /// Use a instant command generator instead of clients and mempools.
    ///
    /// In this way, end-to-end latency **cannot** be measured.
    pub(crate) use_instant_generator: bool,
    /// Transaction per second.
    pub(crate) injection_rate: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            use_instant_generator: false,
            injection_rate: 10_000_000,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub(crate) enum ConsensusType {
    ROPSCON,
}

impl Default for ConsensusType {
    fn default() -> Self {
        Self::ROPSCON
    }
}

impl std::fmt::Display for ConsensusType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ROPSCON => write!(f, "ropscon"),
        }
    }
}

impl ConsensusType {

}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct TestMode {
    #[serde(default)]
    pub(crate) delay_test: bool,
    #[serde(default)]
    pub(crate) memory_test: bool,
    #[serde(default)]
    pub(crate) fault_tolerance_test: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
pub(crate) struct Logs {}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub(crate) struct Metrics {
    /// Enable metrics module.
    enabled: bool,
    /// Stop the node if finalized block is higher than this value.
    /// If not set, the node will run forever.
    pub(crate) stop_after: Option<u64>,
    /// Print every finalization logs.
    pub(crate) trace_finalization: bool,
    /// Report metrics every `sampling_interval` ms.
    pub(crate) sampling_interval: u64,
    /// Export the metrics data to the `export_path` before the node exits.
    pub(crate) export_path: Option<PathBuf>,
    /// Track last `n` sampling data.
    pub(crate) sampling_window: usize,
    /// Stop the node after mean latency and throughput are stable.
    pub(crate) stop_after_stable: bool,
    /// Stable threshold for mean latency and throughput.
    pub(crate) stable_threshold: f64,
    /// Print the metrics data to stdout every n samples.
    /// If not provided, never report.
    pub(crate) report_every_n_samples: Option<usize>,
    /// Stop the node after `n` samples.
    /// If not provided, never stop.
    pub(crate) stop_after_n_samples: Option<usize>,
}

impl Default for Metrics {
    fn default() -> Self {
        Self {
            enabled: true,
            stop_after: None,
            trace_finalization: false,
            sampling_interval: 250,
            export_path: None,
            stop_after_stable: true,
            stable_threshold: 1.0,
            sampling_window: 40,
            report_every_n_samples: Some(8),
            stop_after_n_samples: Some(400),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct NodeConfig {
    id: u64,
    public_key: AffinePoint,
    private_key: Scalar,
    mpk:AffinePoint,
    pre:(AffinePoint,AffinePoint),
    spre:(Scalar, Scalar),
    i_to_X: HashMap<u64, AffinePoint>,
    // id, addr
    peer_addrs: BTreeMap<u64, SocketAddr>,

    #[serde(default)]
    node_settings: NodeSettings,
    #[serde(default)]
    consensus: ConsensusType,
    #[serde(default)]
    test_mode: TestMode,
    #[serde(default)]
    logs: Logs,
    #[serde(default)]
    metrics: Metrics,
    #[serde(default)]
    client: ClientConfig,
}

impl Default for NodeConfig {
    fn default() -> Self {
        let mut peer_addrs = BTreeMap::new();
        let mut i_to_X = HashMap::new();
        let (public_key, private_key) = generate_keypair();
        let i = 1;
        i_to_X.insert(i, ProjectivePoint::to_affine(&public_key));
        let (d_i, e_i, D_i, E_i) = pre_round();
        peer_addrs.insert(
            1u64,
            "localhost:8123".to_socket_addrs().unwrap().next().unwrap(),
        );

        Self {
            id:1u64,
            public_key:ProjectivePoint::to_affine(&public_key),
            private_key,
            mpk:ProjectivePoint::to_affine(&public_key),
            pre:(ProjectivePoint::to_affine(&D_i), ProjectivePoint::to_affine(&E_i)),
            spre:(d_i, e_i),
            i_to_X,
            peer_addrs,
            node_settings: NodeSettings::default(),
            consensus: ConsensusType::default(),
            test_mode: TestMode::default(),
            logs: Logs::default(),
            metrics: Metrics::default(),
            client: ClientConfig::default(),
        }
    }
}

impl NodeConfig {
    pub fn from_cli(cli: &Cli) -> Result<Self, ConfigError> {
        let config = match &cli.config {
            Some(path) => {
                let settings = config::Config::builder()
                    .add_source(config::File::with_name(path.to_str().unwrap()))
                    .add_source(config::Environment::with_prefix("ROPSCON"))
                    .build()
                    .unwrap();

                Ok(settings.try_deserialize()?)
            }
            None => Ok(Default::default()),
        };

        // Override the config with cli options.
        config.map(|mut cfg: NodeConfig| {
            if cfg.metrics.export_path.is_none() {
                cfg.metrics.export_path = cli.export_path.clone();
            }

            if cli.disable_metrics {
                cfg.metrics.enabled = false;
            }

            if cli.pretend_crash {
                cfg.node_settings.pretend_crash = true;
            }

            if cli.pretend_malicious {
              cfg.node_settings.pretend_malicious = true;
            }

            if let Some(v) = cli.rate {
                cfg.client.injection_rate = v;
            }

            if let Some(v) = cli.transaction_size {
                cfg.node_settings.transaction_size = v;
            }

            if let Some(v) = cli.batch_size {
                cfg.node_settings.batch_size = v;
            }

            if let Some(v) = cli.leader_rotation {
                cfg.node_settings.leader_rotation = v;
            }

            if let Some(v) = cli.mempool_size {
                cfg.node_settings.mempool_size = v;
            }

            if let Some(v) = cli.timeout {
                cfg.node_settings.timeout = v
            }

            cfg
        })
    }

    pub fn clone_with_keypair(&self, id: u64, public_key:AffinePoint, private_key: Scalar, mpk:AffinePoint) -> Self {
        let mut config = self.clone();
        config.id = id;
        config.mpk = mpk;
        config.public_key = public_key;
        config.private_key = private_key;
        config
    }

    pub fn get_id(&self) -> u64 {
        self.id
    }

    pub fn get_pub(&self) -> ProjectivePoint {
      ProjectivePoint::from(self.public_key)
    }

    pub fn get_mpk(&self) -> ProjectivePoint {
      ProjectivePoint::from(self.mpk)
    }

    pub fn get_local_addr(&self) -> Result<&SocketAddr> {
        self.peer_addrs
            .get(&self.id)
            .ok_or_else(|| ConfigError::LocalAddrError.into())
    }

    pub fn get_peer_addrs(&self) -> HashMap<u64, SocketAddr> {
        let mut ret = HashMap::new();
        for (k, v) in &self.peer_addrs {
            ret.insert(*k, *v);
        }
        ret
    }

    pub fn get_consensus_type(&self) -> &ConsensusType {
        &self.consensus
    }

    #[allow(dead_code)]
    pub fn get_test_mode(&self) -> &TestMode {
        &self.test_mode
    }

    pub fn get_node_settings(&self) -> &NodeSettings {
        &self.node_settings
    }

    pub fn get_metrics(&self) -> &Metrics {
        &self.metrics
    }

    pub fn get_voter_set(&self) -> VoterSet {
        let v: Vec<_> = self.peer_addrs.keys().cloned().collect();
        VoterSet::new(v)
    }

    pub fn override_voter_set(&mut self, voter_set: &VoterSet) {
        let mut peer_addrs = BTreeMap::new();
        voter_set.iter().for_each(|id| {
            peer_addrs.insert(
                *id,
                "localhost:8123".to_socket_addrs().unwrap().next().unwrap(),
            );
        });

        self.peer_addrs = peer_addrs;
    }


    pub fn get_client_config(&self) -> &ClientConfig {
        &self.client
    }

    pub fn set_peer_addrs(&mut self, peer_addrs: BTreeMap<u64, SocketAddr>) {
        self.peer_addrs = peer_addrs;
    }

    pub fn set_i_to_X(&mut self, i_to_X: HashMap<u64, AffinePoint>) {
        self.i_to_X = i_to_X;
    }

    pub fn get_i_to_X(&mut self)->HashMap<u64, AffinePoint> {
      self.i_to_X.clone()
  }

  pub fn get_i_to_X_projective(&mut self)->HashMap<u64, ProjectivePoint> {
    self.i_to_X
        .iter()
        .map(|(&k, v)| (k, ProjectivePoint::from(v)))
        .collect()
}

    pub fn dry_run(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    #[allow(dead_code)]
    pub fn export(&self, full_path: &Path) -> Result<()> {
        let mut file = File::create(full_path)?;
        let content = self.dry_run()?;
        file.write_all(content.as_bytes())?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn disable_metrics(&mut self) {
        self.metrics.enabled = false;
    }

    pub fn set_pretend_crash(&mut self) {
        self.node_settings.pretend_crash = true;
    }

    pub fn set_pretend_malicious(&mut self) {
        self.node_settings.pretend_malicious = true;
    }


    // pub fn sign(&self, msg: &[u8]) -> Signature {
    //     self.private_key.sign(msg)
    // }
    pub fn presign(&mut self){
      let (d_i, e_i, D_i, E_i) = pre_round();
      self.pre = (ProjectivePoint::to_affine(&D_i), ProjectivePoint::to_affine(&E_i));
      self.spre = (d_i, e_i);
    }

    pub fn share_val(&self, ctx: &SessionContext, i: u64, s_i: Scalar) -> bool{
      share_val(ctx,i,s_i)
    }

    pub fn get_pre(&self)->(AffinePoint,AffinePoint){
      self.pre.clone()
    }

    pub fn get_spre(&self)->(Scalar,Scalar){
      self.spre.clone()
    }

    pub fn sign(&self, msg: Digest, T: &[Scalar], pre: (ProjectivePoint, ProjectivePoint))-> Scalar{
        let spre_i = self.spre.clone();
        if self.node_settings.pretend_malicious{
          // A malicious node interferes with consensus reaching by sending wrong shares.
          let wrong_msg = Digest::default();
          sign_round(self.get_mpk(), &wrong_msg.to_vec(), T, pre, self.get_id(), *self.get_private_key(), spre_i)
        }else{
          sign_round(self.get_mpk(), &msg.to_vec(), T, pre, self.get_id(), *self.get_private_key(), spre_i)
        }
        
    }

  //   pub fn sign_test(&self, msg: Vec<u8>, T: &[Scalar], pre: (ProjectivePoint, ProjectivePoint))-> Scalar{
  //     let spre_i = self.spre.clone();
  //     sign_round(self.get_mpk(), &msg, T, pre, self.get_id(), *self.get_private_key(), spre_i)
  // }

    pub fn single_sign(&self, msg: Digest) -> Scalar {
      H("sig", &[&self.get_mpk().clone().to_bytes(), &msg.to_vec(), &ProjectivePoint::from(self.get_pre().0).to_bytes(), &ProjectivePoint::from(self.get_pre().1).to_bytes()])
    }

    // Single-signature verification, hardly used in ROPSCON, skipped for now.
    pub fn single_verify(&self, scalar1: Scalar) -> bool {
      true
    }

    pub fn get_private_key(&self) -> &Scalar {
        &self.private_key
    }

    pub fn verify(&self, msg: Digest, sig: (AffinePoint, Scalar)) -> bool{
        let (R,s) = sig;
        raw_verify(self.get_mpk(), &msg.to_vec(), (ProjectivePoint::from(R), s))
    }
}

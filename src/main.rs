#![feature(drain_filter)]
// TODO: metrics critical path to see what affects performance.

use crate::config_gen::DistributionPlan;
use std::{
    fs::{self, File},
    io::Write,
    path::{Path, PathBuf},
    collections::HashMap,
};

use clap::Parser;
use cli::{Cli, Commands};
use consensus::VoterSet;
use crate::tsalg::generate_keypairs;
use network::{FailureNetwork, MemoryNetwork, TcpNetwork};
use node::Node;

use anyhow::Result;

mod cli;
mod client;
mod config_gen;
mod consensus;
mod coordinator;
mod curve;
mod data;
mod mempool;
mod metrics;
mod network;
mod node;
mod nodeconf;
mod shamir;
mod tsalg;

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let mut config = crate::nodeconf::NodeConfig::from_cli(&cli)?;

    tracing_subscriber::fmt::init();

    match cli.command {
        Some(Commands::MemoryTest { number }) => {
            let (mpk, voter_set) = generate_keypairs(number as u64);
            let genesis = data::Block::genesis();
            let mut i_to_X = HashMap::new();
            voter_set
            .iter()
            .enumerate()
            .for_each(|(idx, (id, pub_key, _priv_key))| {
                i_to_X.insert(
                  *id,
                  *pub_key,
              );
            });

            let mut network = MemoryNetwork::new();

            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.iter().map(|(id,_, _)| *id).collect(),
            ));
            config.set_i_to_X(i_to_X.clone());

            // Prepare the environment.
            let nodes: Vec<_> = voter_set
                .into_iter()
                .map(|(id, publ, secret)| {
                    let adaptor = network.register(id);
                    Node::new(
                        config.clone_with_keypair(id, publ, secret, mpk),
                        adaptor,
                        genesis.to_owned(),
                    )
                })
                .collect();

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            nodes.get(0).unwrap().metrics();

            // Run the nodes.
            nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });

            let _ = tokio::join!(handle);
        }
        Some(Commands::CrashTest { number }) => {
            let total = number * 3 + 1;
            let (mpk, voter_set)= generate_keypairs(total as u64);
            let genesis = data::Block::genesis();
            let mut network = MemoryNetwork::new();
            let mut i_to_X = HashMap::new();
            voter_set
            .iter()
            .enumerate()
            .for_each(|(idx, (id, pub_key, _priv_key))| {
                i_to_X.insert(
                  *id,
                  *pub_key,
              );
            });


            // Mock peers
            config.override_voter_set(&VoterSet::new(
                voter_set.iter().map(|(id,_, _)| *id).collect(),
            ));
            config.set_i_to_X(i_to_X.clone());

            // Prepare the environment.
            let nodes: Vec<_> = voter_set
                .iter()
                .enumerate()
                .filter_map(|(idx, (id, p, sec))| {
                    if idx % 3 == 1 {
                        // Fail the node.
                        None
                    } else {
                        let adaptor = network.register(*id);
                        Some(Node::new(
                            config.clone_with_keypair(*id, *p, sec.clone(), mpk),
                            adaptor,
                            genesis.to_owned(),
                        ))
                    }
                })
                .collect();

            // Boot up the network.
            let handle = tokio::spawn(async move {
                network.dispatch().await?;
                Ok::<_, anyhow::Error>(())
            });

            nodes.get(0).unwrap().metrics();

            // Run the nodes.
            nodes.into_iter().for_each(|node| {
                node.spawn_run();
            });

            let _ = tokio::join!(handle);
        }
        Some(Commands::MaliciousTest { number }) => {
          let total = number * 3 + 1;
          let (mpk, voter_set)= generate_keypairs(total as u64);
          let genesis = data::Block::genesis();
          let mut network = MemoryNetwork::new();
          let mut i_to_X = HashMap::new();
          voter_set
          .iter()
          .enumerate()
          .for_each(|(idx, (id, pub_key, _priv_key))| {
              i_to_X.insert(
                *id,
                *pub_key,
            );
          });


          // Mock peers
          config.override_voter_set(&VoterSet::new(
              voter_set.iter().map(|(id,_, _)| *id).collect(),
          ));
          config.set_i_to_X(i_to_X.clone());

          // Prepare the environment.
          let nodes: Vec<_> = voter_set
              .iter()
              .enumerate()
              .filter_map(|(idx, (id, p, sec))| {
                  if idx % 3 == 1 {
                    let adaptor = network.register(*id);
                    let mut mconf = config.clone_with_keypair(*id, *p, sec.clone(), mpk);
                    mconf.set_pretend_malicious();
                    Some(Node::new(
                        mconf,
                        adaptor,
                        genesis.to_owned(),
                    ))
                  } else {
                      let adaptor = network.register(*id);
                      Some(Node::new(
                          config.clone_with_keypair(*id, *p, sec.clone(), mpk),
                          adaptor,
                          genesis.to_owned(),
                      ))
                  }
              })
              .collect();

          // Boot up the network.
          let handle = tokio::spawn(async move {
              network.dispatch().await?;
              Ok::<_, anyhow::Error>(())
          });

          nodes.get(0).unwrap().metrics();

          // Run the nodes.
          nodes.into_iter().for_each(|node| {
              node.spawn_run();
          });

          let _ = tokio::join!(handle);
      }
        Some(Commands::ConfigGen {
            number,
            mut hosts,
            mut export_dir,
            write_file,
            crash_nodes,
            malicious_nodes,
            auto_naming,
        }) => {
            if !auto_naming && export_dir.is_none() {
                panic!("export_dir must be specified when auto_naming is false");
            } else if auto_naming && export_dir.is_none() {
                let mut i = 0;
                while Path::new(&format!("config_{}", i)).exists() {
                    i += 1;
                }

                let name = format!("config_{}", i);

                export_dir = Some(PathBuf::from(name));
            }

            let export_dir = export_dir.expect("export_dir must be specified");

            // println!("Generating config {:?}", cfg);
            if hosts.is_empty() {
                println!("No hosts provided, use localhost instead.");
                hosts.push(String::from("localhost"))
            }

            let distribution_plan = DistributionPlan::new(number, hosts, config, crash_nodes, malicious_nodes);

            if !write_file {
                for (path, content) in distribution_plan.dry_run(&export_dir)? {
                    println!("{}", path.display());
                    println!("{}", content);
                }
            } else {
                if !Path::new(&export_dir).is_dir() {
                    fs::create_dir_all(&export_dir)?;
                }

                for (path, content) in distribution_plan.dry_run(&export_dir)? {
                    let dir = path.parent().unwrap();
                    if !dir.exists() {
                        fs::create_dir(dir)?;
                    }
                    let mut file = File::create(path)?;
                    file.write_all(content.as_bytes())?;
                }
            }
        }
        None => {
            let adapter = if config.get_node_settings().pretend_crash {
                FailureNetwork::spawn(config.get_local_addr()?.to_owned(), config.get_peer_addrs())
            } else {
                TcpNetwork::spawn(config.get_local_addr()?.to_owned(), config.get_peer_addrs())
            };

            tokio::time::sleep(tokio::time::Duration::from_millis(1000)).await;

            let node = Node::new(config, adapter, data::Block::genesis());

            if !cli.disable_metrics {
                node.metrics();
            }

            // Run the node
            let handle = node.spawn_run();

            let _ = handle.await;
        }
    }
    Ok(())
}

//test
#[cfg(test)]
mod test {}

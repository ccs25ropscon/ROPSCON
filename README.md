# ROPSCON

## Quick Start (Runs in debug mode by default)

Directly executing a binary will start a committee composed of a single node using localhost TCP for communication.

```Bash
cargo r
```

### Some other test methods.

#### Single replica via TCP:

```Bash
cargo run
```

#### Replicas via memory network

```Bash
cargo run -- memory-test
```

You can also specify the number of replicas by using "memory-test -n [number]", which defaults to 4.

#### Crash test over memory network

```Bash
cargo run -- crash-test
```

You can also specify the number of crash replicas by using "crash-test -n [number]", which defaults to 1 (of 4).

#### Byzantine test over memory network

```Bash
cargo run -- malicious-test
```

You can also specify the number of crash replicas by using "malicious-test -n [number]", which defaults to 1 (of 4).

#### Distributes locally

```Bash
cargo r -- config-gen --number 4 localhost --export-dir configs -w
```


## Running in release mode (better performance, recommended)

```Bash
cargo build --release
```
Find ropscon under target/release, run
```Bash
./ropscon -h
```
as well as
```Bash
./ropscon config-gen --help
```
to view parameter definitions.

The subcommand `config-gen` provide a way to generate multiple files for multi replicas over multi hosts.
It also helps to generate a bunch of bash scripts to distribute files in accordance, run all the nodes, and
collect the results.

Please lookup the document of config-gen before using it.

**Remember that, default `config-gen` will run in dry-run mode, in which all the files will be print to the console.
By specify `-w` you can flush these files to disks.**

Let's say we want four replicas to reach consensus on localhost

Create a new localhost folder in the parent directory and generate relevant configuration files (injection rate: 5000, batch size: 250, transaction size: 128, timeout: 10000ms):

```Bash
./ropscon -r 5000 -b 250 -t 128 --timeout 10000 config-gen -n 4 -e ../ -w localhost
```

 Then copy ropscon to the localhost directory and run 
 ```Bash
 bash run.sh 
```
(View more specific logs, including the process of ABSE, by adding 'RUST_LOG=TRACE' to the process)


## Multi-host Config Generation

Let's say we want to distribute 4 replicas over 2 hosts (IP_OF_SERVER_1, IP_OF_SERVER_2).

```Bash
./ropscon config-gen --number 4 IP_OF_SERVER_1 IP_OF_SERVER_2 --export-dir configs -w
```

Now, some files are exported in `./configs`.

Then, distribute these files to corresponding servers.

**Please make sure you have right to login servers via `ssh IP_OF_SERVER`.**

```
cd ./configs

bash run-all.sh
```

This script will distribute configs, run replicas, and collect experiment results into your local directory.

## Testing

### How is the test work flow?

First, we can try to export a basic config file. (This can be optional)
And you can edit further `base_config.json` if you like.

```
cargo r -- --export-path base_config.json
```

Next, You will use `config-gen` to generate all the files for a committee in a single tests.

```
cargo r -- --config base_config.json config-gen --number <NUMBER> IPs_OF_SERVER --export-dir configs -w
```

If you skip the first step, then just run (default config will be used):

```
cargo r -- config-gen --number <NUMBER> IPs_OF_SERVER --export-dir configs -w
```

As the section above, run:

```
cd configs/
bash run-all.sh
```

Then you'll get the results.

### How performance is calculated in this work?

In our implmentation, there are three timestamps for a single transaction.

1. T1: A timestamp when transaction is created.
2. T2: A timestamp when block is packed by consensus node.
3. T3: A timestamp when it's finalized in a block.

End-to-end performance is calculated via T1 and T3, and 
Consensus performance is calculated via T2 and T3.


## Some notes related to the code

I. Since ROPSCON relies on the robust threshold signature framework, and the efficiency of threshold signatures is related to server performance, it is not recommended to run a large number of nodes on a generally configured server or PC, with resulting problems including, but not limited to:

1. Throughput is much less than expected (most common), e.g., throughput plummets when increasing the number of nodes.

2. Frequent timeouts when nodes do not contain crash nodes.

3. Running stuck.

4. Consensus run chaos with abnormal blockchain structure or state.

II. The node can pretend to be:

1. A crash node ("--crash-nodes [number]" or "-c [number] or "crash-test"). A crash node will not respond to any incoming messages.

2. A Byzantine node ("--malicious-nodes [number]" or "-m [number] or "malicious-test"). A Byzantine node will send wrong signature shares (votes) for any proposal to interfere with the consensus reaching. It should be noted that apart from the malicious behavior described above, Byzantine nodes will follow the normal consensus process, e.g. it will propose correctly as a non-faulty node.

III.  Rust version used for compilation: rustc 1.67.0-nightly.

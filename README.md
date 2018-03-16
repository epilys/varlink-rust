# varlink for rust

[![Build Status](https://travis-ci.org/varlink/rust.svg?branch=master)](https://travis-ci.org/varlink/rust)

## Example usage
Look into the examples directory. ```build.rs``` contains the magic, which will build rust bindings for the varlink interface definition file.

## varlink file validator
```
$ cd varlink_parser
$ cargo run --example validate examples/io_systemd_network/io.systemd.network.varlink 
    Finished dev [unoptimized + debuginfo] target(s) in 0.0 secs
     Running `target/debug/examples/validate examples/io_systemd_network/io.systemd.network.varlink`
Syntax check passed!

interface io.systemd.network
type Netdev (ifindex: int, ifname: string)
type NetdevInfo (ifindex: int, ifname: string)
method Info(ifindex: int) -> (info: NetdevInfo)
method List() -> (netdevs: Netdev[])
error InvalidParameter (field: string)
error UnknownNetworkDevice ()
```

## varlink rust generator
```rust
$ cd varlink
$ cargo run --bin varlink-generator .../examples/varlink-server-example/src/io.systemd.network.varlink
    Finished dev [unoptimized + debuginfo] target(s) in 0.0 secs
     Running `target/debug/examples/varlink-generator examples/io_systemd_network/io.systemd.network.varlink`
// This file is automatically generated by the varlink rust generator
[...]
```

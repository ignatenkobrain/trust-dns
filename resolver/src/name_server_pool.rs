// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

use std::cmp::Ordering;
use std::collections::BinaryHeap;
use std::io;
use std::time::Duration;

use futures::{Future, Sink};

use trust_dns::error::*;
use trust_dns::client::{BasicClientHandle, ClientHandle};
use trust_dns::op::{Edns, Message};

use config::{NameServerConfig, ResolverConfig, ResolverOpts};

/// State of a connection with a remote NameServer.
#[derive(Clone, Debug)]
enum NameServerState {
    /// Initial state, if Edns is not none, then Edns will be requested
    Init { send_edns: Option<Edns> },
    /// There has been successful communication with the remote.
    ///  if no Edns is associated, then the remote does not support Edns
    Established { remote_edns: Option<Edns> },
    /// For some reason the connection failed. For UDP this would only be a timeout
    ///  for TCP this could be either Connection could never be established, or it
    ///  failed at some point after. The Failed state should not be entered due to the
    ///  error contained in a Message recieved from the server. In All cases to reestablish
    ///  a new connection will need to be created.
    Failed {
        error: ClientError,
        chrono: Duration,
    },
}

impl NameServerState {
    fn to_usize(&self) -> usize {
        match *self {
            NameServerState::Init { .. } => 3,
            NameServerState::Established { .. } => 2,
            NameServerState::Failed { .. } => 1,
        }
    }
}

impl Ord for NameServerState {
    fn cmp(&self, other: &Self) -> Ordering {
        self.to_usize().cmp(&other.to_usize())
    }
}

impl PartialOrd for NameServerState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServerState {
    fn eq(&self, other: &Self) -> bool {
        self.to_usize() == other.to_usize()
    }
}

impl Eq for NameServerState {}

#[derive(Clone)]
pub(crate) struct NameServer {
    config: NameServerConfig,
    client: BasicClientHandle,
    state: NameServerState,
    successes: usize,
    failures: usize,
}

impl NameServer {
    pub fn new(config: NameServerConfig) -> Self {
        unimplemented!()
    }
}

impl ClientHandle for NameServer {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        self.client.send(message)
    }
}

impl Ord for NameServer {
    /// Custom implementation of Ord for NameServer which incorporates the performance of the connection into it's ranking
    fn cmp(&self, other: &Self) -> Ordering {
        // if they are literally equal, just return
        if self == other {
            return Ordering::Equal;
        }

        // TODO: evaluate last failed, and if it's greater that retry period, treat like it's "init"
        // otherwise, run our evaluation to determine the next to be returned from the Heap
        match self.state.cmp(&other.state) {
            Ordering::Equal => (),
            o @ _ => return o,
        }

        // TODO: track latency and use lowest latency connection...

        // invert failure comparison
        if self.failures <= other.failures {
            return Ordering::Greater;
        }

        // at this point we'll go with the lesser of successes to make sure there is ballance
        self.successes.cmp(&other.successes)
    }
}

impl PartialOrd for NameServer {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for NameServer {
    /// NameServers are equal if the config (connection information) are equal
    fn eq(&self, other: &Self) -> bool {
        self.config == other.config
    }
}

impl Eq for NameServer {}

#[derive(Clone)]
pub(crate) struct NameServerPool {
    conns: BinaryHeap<NameServer>,
}

impl NameServerPool {
    pub fn from_config(config: &ResolverConfig, opts: &ResolverOpts) -> NameServerPool {
        let conns: BinaryHeap<NameServer> = config
            .name_servers()
            .iter()
            .map(|ns_config| NameServer::new(ns_config.clone()))
            .collect();

        unimplemented!()
    }
}

impl ClientHandle for NameServerPool {
    fn send(&mut self, message: Message) -> Box<Future<Item = Message, Error = ClientError>> {
        // select the highest priority connection

        unimplemented!()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{SocketAddr, IpAddr, Ipv4Addr};

    use tokio_core::reactor::Core;

    use trust_dns::client::{BasicClientHandle, ClientHandle};
    use trust_dns::op::ResponseCode;
    use trust_dns::rr::{DNSClass, Name, RecordType};

    use config::Protocol;
    use super::*;

    #[test]
    fn test_name_server() {
        let config = NameServerConfig {
            socket_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 52),
            protocol: Protocol::Udp,
        };
        let mut name_server = NameServer::new(config);

        let name = Name::parse("www.example.com.", None).unwrap();
        let mut io_loop = Core::new().unwrap();
        let response = io_loop
            .run(name_server.query(name.clone(), DNSClass::IN, RecordType::A))
            .expect("query failed");
        assert_eq!(response.response_code(), ResponseCode::NoError);
    }
}
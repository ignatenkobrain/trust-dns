// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver

use std::collections::HashMap;
use std::io;
use std::mem;
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use futures::{Async, future, Future, Poll};
use futures::task::park;

use trust_dns::client::{ClientFuture, ClientHandle};
use trust_dns::error::ClientError;
use trust_dns::op::{Message, Query};
use trust_dns::rr::{DNSClass, Name, RData, RecordType};

use config::{ResolverConfig, ResolverOpts};

/// A Recursive Resolver for DNS records.
pub struct Resolver<C: ClientHandle> {
    config: ResolverConfig,
    options: ResolverOpts,
    client: C,
}

impl<C: ClientHandle> Resolver<C> {
    /// Construct a new Resolver with the associated Client.
    pub fn new(config: ResolverConfig, options: ResolverOpts, client: C) -> Self {
        Resolver {
            config,
            options,
            client,
        }
    }

    /// A basic host name lookup lookup
    pub fn lookup(&mut self, host: &str) -> Box<Future<Item = Vec<IpAddr>, Error = io::Error>> {
        let name = match Name::parse(host, None) {
            Ok(name) => name,
            Err(err) => return Box::new(future::err(io::Error::from(err))),
        };

        // create the lookup
        let query = LookupIpState::lookup(name, RecordType::A, &mut self.client);
        Box::new(query)
    }
}

struct LookupStack(Vec<Query>);

impl LookupStack {
    // pushes the Query onto the stack, and returns a reference. An error will be returned
    fn push(&mut self, query: Query) -> io::Result<&Query> {
        if self.0.contains(&query) {
            return Err(io::Error::new(io::ErrorKind::Other, "circular CNAME or other recursion"));
        }

        self.0.push(query);
        Ok(self.0.last().unwrap())
    }
}

enum LookupIpState {
    Query(RecordType, Box<Future<Item = Message, Error = ClientError>>),
    Fin(Vec<IpAddr>),
}

impl LookupIpState {
    fn lookup<C: ClientHandle>(name: Name, query_type: RecordType, client: &mut C) -> Self {
        let query_future = client.query(name, DNSClass::IN, query_type);
        LookupIpState::Query(query_type, query_future)
    }

    fn transition_query(&mut self, message: &Message) {
        assert!(if let LookupIpState::Query(_, _) = *self {
                    true
                } else {
                    false
                });

        // TODO: evaluate all response settings, like truncation, etc.
        let answers = message
            .answers()
            .iter()
            .filter_map(|r| if let RData::A(ipaddr) = *r.rdata() {
                            Some(IpAddr::V4(ipaddr))
                        } else {
                            None
                        })
            .collect();

        mem::replace(self, LookupIpState::Fin(answers));
    }
}

impl Future for LookupIpState {
    type Item = Vec<IpAddr>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, Self::Error> {
        // first transition any polling that is needed (mutable refs...)
        let poll;
        match *self {
            LookupIpState::Query(_, ref mut query) => {
                poll = query.poll().map_err(io::Error::from);
                match poll {
                    Ok(Async::NotReady) => {
                        return Ok(Async::NotReady);
                    }
                    Ok(Async::Ready(_)) => (), // handled in next match
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            LookupIpState::Fin(ref mut ips) => {
                let ips = mem::replace(ips, Vec::<IpAddr>::new());
                return Ok(Async::Ready(ips));
            }
        }

        // getting here means there are Aync::Ready available.
        match *self {
            LookupIpState::Query(_, _) => {
                match poll {
                    Ok(Async::Ready(ref message)) => self.transition_query(message),
                    _ => panic!("should have returned earlier"),
                }
            }
            LookupIpState::Fin(_) => panic!("should have returned earlier"),
        }

        park().unpark(); // yield
        Ok(Async::NotReady)
    }
}

#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use std::net::{Ipv4Addr, ToSocketAddrs};
    use self::tokio_core::reactor::Core;
    use trust_dns::udp::UdpClientStream;

    use super::*;

    #[test]
    fn test_lookup() {
        let mut io_loop = Core::new().unwrap();
        let addr: SocketAddr = ("8.8.8.8", 53)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let (stream, sender) = UdpClientStream::new(addr, io_loop.handle());
        let mut client = ClientFuture::new(stream, sender, io_loop.handle(), None);
        let mut resolver =
            Resolver::new(ResolverConfig::default(), ResolverOpts::default(), client);

        io_loop
            .run(resolver
                     .lookup("www.example.com.")
                     .map(move |response| {
                              println!("response records: {:?}", response);

                              let address = response[0];
                              assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)))
                          })
                     .map_err(|e| {
                                  assert!(false, "query failed: {}", e);
                              }))
            .unwrap();
    }
}

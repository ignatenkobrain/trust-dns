// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver

use std::cell::RefCell;
use std::io;

use futures::Stream;
use tokio_core::reactor::Core;
use trust_dns::client::{BasicClientHandle, ClientConnection, ClientFuture};

use config::{ResolverConfig, ResolverOpts};
use lookup_ip::LookupIp;
use ResolverFuture;

/// The result of a Host (basic A or AAAA) query
pub struct Resolver {
    resolver_future: RefCell<ResolverFuture>,
    io_loop: RefCell<Core>,
}


impl Resolver {
    /// Construct a new Resolver with the given ClientConnection, see UdpClientConnection and/or TcpCLientConnection
    ///
    /// # Arguments
    /// * `config` - configuration for the resolver
    /// * `options` - resolver options for performing lookups
    /// * `client_connection` - ClientConnection for establishing the connection to the DNS server
    ///
    /// # Returns
    /// A new Resolver
    pub fn new(config: ResolverConfig, options: ResolverOpts) -> io::Result<Self> {
        let io_loop = Core::new()?;
        let resolver = ResolverFuture::new(config, options);

        Ok(Resolver {
               resolver_future: RefCell::new(resolver),
               io_loop: RefCell::new(io_loop),
           })
    }

    /// Performs a DNS lookup for the IP for the given hostname.
    ///
    /// Based on the configuration and options passed in, this may do either a A or a AAAA lookup,
    ///  returning IpV4 or IpV6 addresses.
    ///
    /// # Arguments
    /// * `host` - string hostname, if this is an invalid hostname, an error will be thrown.
    pub fn lookup_ip(&mut self, host: &str) -> io::Result<LookupIp> {
        self.io_loop
            .borrow_mut()
            .run(self.resolver_future.borrow_mut().lookup_ip(host))
    }
}

#[cfg(test)]
mod tests {
    extern crate tokio_core;

    use futures::Future;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, ToSocketAddrs};
    use self::tokio_core::reactor::Core;
    use trust_dns::client::ClientFuture;
    use trust_dns::udp::UdpClientConnection;

    use super::*;

    #[test]
    fn test_lookup() {
        let addr: SocketAddr = ("8.8.8.8", 53)
            .to_socket_addrs()
            .unwrap()
            .next()
            .unwrap();
        let conn = UdpClientConnection::new(addr).unwrap();
        let mut resolver = Resolver::new(ResolverConfig::default(), ResolverOpts::default(), conn);

        let mut response = resolver.lookup_ip("www.example.com.").unwrap();
        println!("response records: {:?}", response);

        let address = response.next().expect("no addresses returned");
        assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    }
}
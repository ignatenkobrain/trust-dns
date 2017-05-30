// Copyright 2015-2017 Benjamin Fry <benjaminfry@me.com>
//
// Licensed under the Apache License, Version 2.0, <LICENSE-APACHE or
// http://apache.org/licenses/LICENSE-2.0> or the MIT license <LICENSE-MIT or
// http://opensource.org/licenses/MIT>, at your option. This file may not be
// copied, modified, or distributed except according to those terms.

//! Structs for creating and using a Resolver

use std::net::IpAddr;

/// The result of a Host (basic A or AAAA) query
pub struct LookupHost {
    ips: Vec<IpAddr>,
}

impl Iterator for LookupHost {
    type Item = IpAddr;

    
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
use socket2::{Domain, Protocol, SockAddr, Socket, Type};
use std::{io, net::SocketAddr};
use tokio::net::TcpListener;

/// Create a reusable non-blocking TCP listener for the direct-transfer
/// protocol. TLS is layered above the returned Tokio listener by the receiver.
pub fn bind_tcp_listener(address: SocketAddr) -> io::Result<TcpListener> {
    let domain = if address.is_ipv4() {
        Domain::IPV4
    } else {
        Domain::IPV6
    };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&SockAddr::from(address))?;
    socket.listen(128)?;
    TcpListener::from_std(socket.into())
}

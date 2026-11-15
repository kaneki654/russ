//! Local-network primitives for interface selection, discovery data, TCP, and
//! the authenticated TLS transfer protocol.

pub mod connection;
pub mod discovery;
pub mod interface;
pub mod ip_detector;
pub mod protocol;
pub mod transfer;

pub use connection::bind_tcp_listener;
pub use discovery::{
    start_discovery, DiscoveryAnnouncement, DiscoveryEvent, DiscoveryHandle, DISCOVERY_PORT,
};
pub use interface::usable_interfaces;
pub use transfer::{run_receiver, send_path, TransferDirection, TransferEvent, TransferSecurity};

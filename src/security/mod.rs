//! Security primitives shared by the authenticated TCP/TLS session.
//!
//! Identity enrollment is local and certificate trust is confirmed explicitly
//! by the user before an unknown peer can transfer data.

pub mod authentication;
pub mod fingerprint;
pub mod identity;
pub mod tls;

pub use authentication::{AuthChallenge, ReplayGuard};
pub use fingerprint::{certificate_fingerprint, normalize_fingerprint};
pub use identity::DeviceIdentity;
pub use tls::{tls13_client_builder, tls13_server_builder};

//! Transfer-engine primitives shared by the TCP/TLS sender and receiver.

pub mod adaptive_optimizer;
pub mod integrity;
pub mod manifest;
pub mod receiver;
pub mod recovery;
pub mod sender;
pub mod streaming;
pub mod transfer_engine;

pub use adaptive_optimizer::{AdaptiveOptimizer, BufferPlan, OptimizerConfig, ThroughputSample};
pub use integrity::{sha256_bytes, sha256_file, verify_file_sha256};
pub use manifest::{
    inspect_file, validate_relative_path, FileInspection, ManifestEntry, TransferManifest,
};
pub use streaming::{BufferPool, CopyProgress, CopyStats, TransferControl};
pub use transfer_engine::TransferEngine;

use super::{
    adaptive_optimizer::{AdaptiveOptimizer, BufferPlan, OptimizerConfig, ThroughputSample},
    streaming::BufferPool,
};
use crate::hardware::HardwareSnapshot;
use std::io;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex,
};

/// Shared transfer-engine owner for GUI and protocol tasks.
#[derive(Clone)]
pub struct TransferEngine {
    optimizer: Arc<Mutex<AdaptiveOptimizer>>,
    active_receivers: Arc<AtomicUsize>,
}

impl TransferEngine {
    pub fn new(profile: HardwareSnapshot, config: OptimizerConfig) -> Self {
        Self {
            optimizer: Arc::new(Mutex::new(AdaptiveOptimizer::new(profile, config))),
            active_receivers: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn current_plan(&self) -> BufferPlan {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .plan()
            .clone()
    }

    pub fn active_receivers(&self) -> usize {
        self.active_receivers.load(Ordering::Acquire)
    }

    pub(crate) fn begin_receive(&self) -> ReceiveGuard {
        self.active_receivers.fetch_add(1, Ordering::AcqRel);
        ReceiveGuard(self.active_receivers.clone())
    }

    pub fn profile(&self) -> HardwareSnapshot {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .profile()
            .clone()
    }

    pub fn buffer_pool(&self) -> io::Result<BufferPool> {
        BufferPool::new(&self.current_plan())
    }

    pub fn replace_profile(&self, profile: HardwareSnapshot) {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .replace_profile(profile);
    }

    pub fn replace_config(&self, config: OptimizerConfig) {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .replace_config(config);
    }

    pub fn observe(&self, sample: ThroughputSample) {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .observe(sample);
    }

    pub fn throughput_bytes_per_second(&self) -> Option<f64> {
        self.optimizer
            .lock()
            .expect("transfer optimizer mutex poisoned")
            .ewma_bytes_per_second()
    }
}

pub(crate) struct ReceiveGuard(Arc<AtomicUsize>);

impl Drop for ReceiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

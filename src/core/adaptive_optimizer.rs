use crate::hardware::HardwareSnapshot;
use serde::{Deserialize, Serialize};
use std::time::Duration;

pub const DEFAULT_MIN_BUFFER_BYTES: usize = 64 * 1024;
pub const DEFAULT_MAX_BUFFER_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_IN_FLIGHT_BYTES: usize = 64 * 1024 * 1024;

/// User-tunable bounds.  The optimizer always normalizes these values before
/// using them, so a malformed persisted config cannot create an unbounded
/// allocation.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OptimizerConfig {
    pub min_buffer_bytes: usize,
    pub max_buffer_bytes: usize,
    pub max_in_flight_bytes: usize,
    pub max_concurrent_files: usize,
}

impl Default for OptimizerConfig {
    fn default() -> Self {
        Self {
            min_buffer_bytes: DEFAULT_MIN_BUFFER_BYTES,
            max_buffer_bytes: DEFAULT_MAX_BUFFER_BYTES,
            max_in_flight_bytes: DEFAULT_MAX_IN_FLIGHT_BYTES,
            max_concurrent_files: 4,
        }
    }
}

impl OptimizerConfig {
    pub fn normalized(&self) -> Self {
        let min_buffer_bytes = self
            .min_buffer_bytes
            .clamp(DEFAULT_MIN_BUFFER_BYTES, DEFAULT_MAX_BUFFER_BYTES);
        let max_buffer_bytes = self
            .max_buffer_bytes
            .clamp(min_buffer_bytes, DEFAULT_MAX_BUFFER_BYTES);
        let minimum_in_flight = min_buffer_bytes.saturating_mul(2);
        let max_in_flight_bytes = self
            .max_in_flight_bytes
            .clamp(minimum_in_flight, DEFAULT_MAX_IN_FLIGHT_BYTES);
        let max_in_flight_bytes = max_in_flight_bytes.max(max_buffer_bytes);
        let max_concurrent_files = self.max_concurrent_files.clamp(1, 16);

        Self {
            min_buffer_bytes,
            max_buffer_bytes,
            max_in_flight_bytes,
            max_concurrent_files,
        }
    }
}

/// A bounded memory plan for one transfer engine instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BufferPlan {
    pub buffer_size_bytes: usize,
    pub max_in_flight_bytes: usize,
    pub concurrent_file_limit: usize,
    pub reason: String,
}

impl BufferPlan {
    pub fn memory_budget_mib(&self) -> f64 {
        self.max_in_flight_bytes as f64 / (1024.0 * 1024.0)
    }
}

#[derive(Clone, Debug)]
pub struct ThroughputSample {
    pub elapsed: Duration,
    pub bytes: u64,
    /// Fraction of the observation window where the writer could not accept
    /// more data immediately.  This is supplied by the transport layer later.
    pub backpressure_ratio: f32,
    /// Fraction of the observation window spent waiting on storage.
    pub io_wait_ratio: f32,
}

impl ThroughputSample {
    pub fn bytes_per_second(&self) -> f64 {
        let seconds = self.elapsed.as_secs_f64();
        if seconds > 0.0 {
            self.bytes as f64 / seconds
        } else {
            0.0
        }
    }
}

/// Conservative adaptive planner.  It operates on observations instead of
/// guessing from file size; this keeps a fast NVMe/LAN path efficient without
/// making a slow disk or a low-memory machine allocate aggressively.
#[derive(Clone, Debug)]
pub struct AdaptiveOptimizer {
    profile: HardwareSnapshot,
    config: OptimizerConfig,
    plan: BufferPlan,
    ewma_bytes_per_second: Option<f64>,
    last_reason: String,
}

impl AdaptiveOptimizer {
    pub fn new(profile: HardwareSnapshot, config: OptimizerConfig) -> Self {
        let config = config.normalized();
        let plan = initial_plan(&profile, &config);
        Self {
            profile,
            config,
            last_reason: plan.reason.clone(),
            plan,
            ewma_bytes_per_second: None,
        }
    }

    pub fn profile(&self) -> &HardwareSnapshot {
        &self.profile
    }

    pub fn config(&self) -> &OptimizerConfig {
        &self.config
    }

    pub fn plan(&self) -> &BufferPlan {
        &self.plan
    }

    pub fn ewma_bytes_per_second(&self) -> Option<f64> {
        self.ewma_bytes_per_second
    }

    pub fn replace_profile(&mut self, profile: HardwareSnapshot) {
        self.profile = profile;
        self.plan = initial_plan(&self.profile, &self.config);
        self.last_reason = self.plan.reason.clone();
        self.ewma_bytes_per_second = None;
    }

    pub fn replace_config(&mut self, config: OptimizerConfig) {
        self.config = config.normalized();
        self.plan = initial_plan(&self.profile, &self.config);
        self.last_reason = self.plan.reason.clone();
    }

    pub fn observe(&mut self, sample: ThroughputSample) {
        let throughput = sample.bytes_per_second();
        self.ewma_bytes_per_second = Some(match self.ewma_bytes_per_second {
            Some(previous) => previous * 0.75 + throughput * 0.25,
            None => throughput,
        });

        let current = self.plan.buffer_size_bytes;
        let config = &self.config;
        let (next, reason) = if sample.backpressure_ratio > 0.35 {
            (
                current
                    .saturating_mul(3)
                    .saturating_div(4)
                    .max(config.min_buffer_bytes),
                "reduced buffer after sustained writer backpressure",
            )
        } else if sample.io_wait_ratio > 0.55 {
            (
                current
                    .saturating_mul(3)
                    .saturating_div(4)
                    .max(config.min_buffer_bytes),
                "reduced buffer while storage is the bottleneck",
            )
        } else if sample.backpressure_ratio < 0.05 && sample.io_wait_ratio < 0.25 {
            (
                current
                    .saturating_mul(5)
                    .saturating_div(4)
                    .min(config.max_buffer_bytes),
                "increased buffer while the path has headroom",
            )
        } else {
            (current, "held buffer after a balanced observation")
        };

        self.plan.buffer_size_bytes = next.clamp(config.min_buffer_bytes, config.max_buffer_bytes);
        self.plan.max_in_flight_bytes = self
            .plan
            .buffer_size_bytes
            .saturating_mul(self.plan.concurrent_file_limit)
            .min(config.max_in_flight_bytes)
            .max(self.plan.buffer_size_bytes);
        self.plan.reason = reason.to_owned();
        self.last_reason = reason.to_owned();
    }

    pub fn last_reason(&self) -> &str {
        &self.last_reason
    }
}

fn initial_plan(profile: &HardwareSnapshot, config: &OptimizerConfig) -> BufferPlan {
    let available = usize::try_from(profile.memory.available_bytes).unwrap_or(usize::MAX);
    let minimum_buffer = config.min_buffer_bytes;
    let minimum_budget = minimum_buffer.saturating_mul(2);

    // At most 1/16 of currently available RAM is considered for transfer
    // buffers, then the user-configured hard ceiling is applied.  The lower
    // bound only guarantees two minimum buffers, never a large allocation.
    let memory_ceiling = available.max(minimum_budget);
    let desired_budget = available.saturating_div(16).max(minimum_budget);
    let max_in_flight_bytes = desired_budget
        .min(config.max_in_flight_bytes)
        .min(memory_ceiling)
        .max(minimum_budget);

    let logical_cores = profile.cpu.logical_cores.max(1);
    let concurrency_by_cpu = (logical_cores / 2).max(1);
    let concurrent_file_limit = concurrency_by_cpu
        .min(config.max_concurrent_files)
        .min((max_in_flight_bytes / minimum_buffer).max(1));

    let network_speed_mbps = profile
        .network
        .interfaces
        .iter()
        .filter(|interface| interface.usable_by_default)
        .filter_map(|interface| interface.link_speed_mbps)
        .max();
    let speed_factor = match network_speed_mbps {
        Some(speed) if speed >= 2_500 => 2,
        Some(speed) if speed >= 1_000 => 1,
        _ => 0,
    };

    let per_file_budget = max_in_flight_bytes
        .saturating_div(concurrent_file_limit.max(1))
        .saturating_div(4)
        .max(minimum_buffer);
    let buffer_size_bytes = per_file_budget
        .saturating_mul(1 + speed_factor)
        .clamp(config.min_buffer_bytes, config.max_buffer_bytes);
    let max_in_flight_bytes = buffer_size_bytes
        .saturating_mul(concurrent_file_limit)
        .min(config.max_in_flight_bytes)
        .max(buffer_size_bytes);

    let reason = format!(
        "{} logical cores, {} available RAM, {} network hint",
        logical_cores,
        crate::hardware::format_bytes(available as u64),
        network_speed_mbps
            .map(|speed| format!("{speed} Mbps"))
            .unwrap_or_else(|| "no link-speed data".to_owned())
    );

    BufferPlan {
        buffer_size_bytes,
        max_in_flight_bytes,
        concurrent_file_limit,
        reason,
    }
}

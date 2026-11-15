use crate::{
    core::{BufferPlan, OptimizerConfig},
    hardware::{format_bytes, HardwareSnapshot},
};
use egui::Ui;

pub fn show(
    ui: &mut Ui,
    config: &mut OptimizerConfig,
    hardware: &HardwareSnapshot,
    plan: &BufferPlan,
) -> bool {
    ui.heading("Security and Performance Settings");
    ui.label("Phase 1–2 settings are local and affect only bounded buffer planning.");
    ui.add_space(8.0);

    let mut changed = false;
    ui.label(egui::RichText::new("Adaptive buffer limits").strong());
    changed |= ui
        .add(
            egui::Slider::new(&mut config.min_buffer_bytes, 64 * 1024..=4 * 1024 * 1024)
                .text("minimum bytes"),
        )
        .changed();
    changed |= ui
        .add(
            egui::Slider::new(&mut config.max_buffer_bytes, 1024 * 1024..=16 * 1024 * 1024)
                .text("maximum bytes"),
        )
        .changed();
    changed |= ui
        .add(
            egui::Slider::new(
                &mut config.max_in_flight_bytes,
                2 * 1024 * 1024..=64 * 1024 * 1024,
            )
            .text("maximum in-flight bytes"),
        )
        .changed();
    changed |= ui
        .add(egui::Slider::new(&mut config.max_concurrent_files, 1..=16).text("concurrent files"))
        .changed();

    ui.separator();
    ui.label(format!(
        "Current recommendation: {} buffer / {} in flight",
        format_bytes(plan.buffer_size_bytes as u64),
        format_bytes(plan.max_in_flight_bytes as u64)
    ));
    ui.label(format!(
        "Available RAM used as input: {}",
        format_bytes(hardware.memory.available_bytes)
    ));
    ui.label("The planner caps transfer memory and responds to measured backpressure; it never reserves all available RAM.");

    ui.separator();
    ui.label(egui::RichText::new("Security status").strong());
    ui.label("TLS 1.3 mutual authentication is active for direct peer transfers.");
    ui.label("No telemetry, relay, or external storage is used by this foundation.");
    changed
}

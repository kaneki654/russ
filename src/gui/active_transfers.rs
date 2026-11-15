use crate::{
    core::BufferPlan,
    gui::{receiver::ReceiverState, sender::SenderState},
    hardware::format_bytes,
};
use egui::Ui;

pub fn show(ui: &mut Ui, sender: &SenderState, receiver: &ReceiverState, plan: &BufferPlan) {
    ui.heading("Active Transfers");
    ui.label("Live transfer state from the bounded Tokio streaming engine.");
    ui.add_space(10.0);

    let mut active = false;
    if sender.running {
        active = true;
        show_transfer(
            ui,
            "Sending",
            &sender.current_path,
            sender.bytes_transferred,
            sender.total_bytes,
            sender.speed_bytes_per_second,
            sender.paused,
        );
    }
    if receiver.transfer_id.is_some() && receiver.running && receiver.total_bytes > 0 {
        active = true;
        show_transfer(
            ui,
            "Receiving",
            &receiver.current_path,
            receiver.bytes_transferred,
            receiver.total_bytes,
            receiver.speed_bytes_per_second,
            receiver.paused,
        );
    }
    if !active {
        ui.label("No active file transfer.");
    }

    ui.separator();
    ui.label(egui::RichText::new("Prepared engine limits").strong());
    ui.label(format!(
        "Read/write buffer: {}",
        format_bytes(plan.buffer_size_bytes as u64)
    ));
    ui.label(format!(
        "Maximum in flight: {}",
        format_bytes(plan.max_in_flight_bytes as u64)
    ));
    ui.label(format!("Concurrent files: {}", plan.concurrent_file_limit));
    ui.label(&plan.reason);
}

fn show_transfer(
    ui: &mut Ui,
    direction: &str,
    current_path: &str,
    bytes_transferred: u64,
    total_bytes: u64,
    speed_bytes_per_second: f64,
    paused: bool,
) {
    ui.group(|ui| {
        ui.label(egui::RichText::new(direction).strong());
        ui.label(if paused { "Paused" } else { "Running" });
        if total_bytes > 0 {
            let progress = bytes_transferred as f32 / total_bytes as f32;
            ui.add(egui::ProgressBar::new(progress.clamp(0.0, 1.0)).show_percentage());
        }
        ui.label(format!(
            "{} / {} · {} · {:.2} MB/s",
            format_bytes(bytes_transferred),
            format_bytes(total_bytes),
            current_path,
            speed_bytes_per_second / 1_048_576.0
        ));
    });
}

use crate::{hardware::format_bytes, storage::TransferHistoryEntry};
use egui::{Grid, Ui};

pub fn show(ui: &mut Ui, history: &[TransferHistoryEntry]) {
    ui.heading("Transfer History");
    if history.is_empty() {
        ui.label("Completed transfer records will appear here after a transfer finishes.");
        return;
    }

    Grid::new("transfer-history")
        .num_columns(6)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Direction");
            ui.label("Peer");
            ui.label("Bytes");
            ui.label("SHA-256");
            ui.label("Time");
            ui.label("Result");
            ui.end_row();
            for entry in history {
                ui.label(&entry.direction);
                ui.label(&entry.peer_device_name);
                ui.label(format_bytes(entry.bytes));
                ui.monospace(entry.sha256.as_deref().unwrap_or("—"));
                ui.label(entry.completed_at_unix_seconds.to_string());
                ui.label(if entry.succeeded { "success" } else { "failed" });
                ui.end_row();
            }
        });
}

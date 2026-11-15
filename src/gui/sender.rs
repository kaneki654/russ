use crate::{core::FileInspection, hardware::format_bytes};
use egui::Ui;
use std::path::PathBuf;

pub struct SenderState {
    pub selected_path: Option<PathBuf>,
    pub inspection: Option<FileInspection>,
    pub hashing: bool,
    pub status: String,
    pub target_address: String,
    pub server_fingerprint: String,
    pub running: bool,
    pub paused: bool,
    pub transfer_id: Option<String>,
    pub current_path: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub speed_bytes_per_second: f64,
}

impl Default for SenderState {
    fn default() -> Self {
        Self {
            target_address: "127.0.0.1:4433".to_owned(),
            ..Self::empty()
        }
    }
}

impl SenderState {
    fn empty() -> Self {
        Self {
            selected_path: None,
            inspection: None,
            hashing: false,
            status: String::new(),
            target_address: String::new(),
            server_fingerprint: String::new(),
            running: false,
            paused: false,
            transfer_id: None,
            current_path: String::new(),
            bytes_transferred: 0,
            total_bytes: 0,
            speed_bytes_per_second: 0.0,
        }
    }
}

pub enum Action {
    PathSelected(PathBuf),
    Start,
    Pause,
    Resume,
    Cancel,
}

pub fn show(ui: &mut Ui, state: &mut SenderState) -> Option<Action> {
    ui.heading("Send Files");
    ui.label("Select a file or folder, then enter the receiver's LAN address.");
    ui.add_space(8.0);

    let mut action = None;
    ui.horizontal(|ui| {
        ui.label("Receiver address:");
        ui.text_edit_singleline(&mut state.target_address);
    });
    ui.horizontal(|ui| {
        ui.label("Receiver SHA-256 fingerprint (optional for first approval):");
        ui.text_edit_singleline(&mut state.server_fingerprint);
    });
    ui.colored_label(
        egui::Color32::from_rgb(120, 210, 150),
        "TLS 1.3 is enabled. A first connection requires explicit fingerprint approval.",
    );
    ui.add_space(6.0);
    ui.horizontal(|ui| {
        if ui.button("Choose file…").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_file() {
                action = Some(Action::PathSelected(path));
            }
        }
        if ui.button("Choose folder…").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                action = Some(Action::PathSelected(path));
            }
        }
    });

    if let Some(path) = &state.selected_path {
        ui.add_space(6.0);
        ui.label(egui::RichText::new("Selected source").strong());
        ui.monospace(path.display().to_string());
    } else {
        ui.add_space(6.0);
        ui.label("Drop a file or folder onto this window, or choose one above.");
    }

    if let Some(inspection) = &state.inspection {
        ui.separator();
        ui.label(format!("Size: {}", format_bytes(inspection.size_bytes)));
        if state.hashing {
            ui.label("SHA-256: calculating in the Tokio worker…");
        } else if let Some(hash) = &inspection.sha256 {
            ui.horizontal(|ui| {
                ui.label("SHA-256:");
                ui.monospace(hash);
            });
        }
    }

    ui.add_space(12.0);
    ui.group(|ui| {
        ui.label(egui::RichText::new("Receiver").strong());
        if state.running {
            ui.label(if state.paused {
                "Transfer paused"
            } else {
                "Transfer running"
            });
            if state.total_bytes > 0 {
                let progress = state.bytes_transferred as f32 / state.total_bytes as f32;
                ui.add(egui::ProgressBar::new(progress.clamp(0.0, 1.0)).show_percentage());
            }
            ui.label(format!(
                "{} / {} · {} · {:.2} MB/s",
                format_bytes(state.bytes_transferred),
                format_bytes(state.total_bytes),
                state.current_path,
                state.speed_bytes_per_second / 1_048_576.0
            ));
            ui.horizontal(|ui| {
                if state.paused {
                    if ui.button("Resume").clicked() {
                        action = Some(Action::Resume);
                    }
                } else if ui.button("Pause").clicked() {
                    action = Some(Action::Pause);
                }
                if ui.button("Cancel").clicked() {
                    action = Some(Action::Cancel);
                }
            });
        } else if ui
            .add_enabled(
                state.selected_path.is_some() && !state.target_address.trim().is_empty(),
                egui::Button::new("Send selected source"),
            )
            .clicked()
        {
            action = Some(Action::Start);
        }
    });
    if !state.status.is_empty() {
        ui.label(&state.status);
    }
    action
}

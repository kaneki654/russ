use crate::hardware::HardwareSnapshot;
use egui::{ComboBox, Grid, Ui};
use std::{net::SocketAddr, path::PathBuf};

pub struct ReceiverState {
    pub output_directory: Option<PathBuf>,
    pub port: String,
    pub selected_interface: Option<String>,
    pub running: bool,
    pub paused: bool,
    pub listening_address: Option<SocketAddr>,
    pub transfer_id: Option<String>,
    pub current_path: String,
    pub bytes_transferred: u64,
    pub total_bytes: u64,
    pub speed_bytes_per_second: f64,
    pub status: String,
}

impl Default for ReceiverState {
    fn default() -> Self {
        Self {
            port: "4433".to_owned(),
            ..Self::empty()
        }
    }
}

impl ReceiverState {
    fn empty() -> Self {
        Self {
            output_directory: None,
            port: String::new(),
            selected_interface: None,
            running: false,
            paused: false,
            listening_address: None,
            transfer_id: None,
            current_path: String::new(),
            bytes_transferred: 0,
            total_bytes: 0,
            speed_bytes_per_second: 0.0,
            status: String::new(),
        }
    }

    pub fn status_reset(&mut self) {
        self.transfer_id = None;
        self.current_path = "waiting for sender".to_owned();
        self.bytes_transferred = 0;
        self.total_bytes = 0;
        self.speed_bytes_per_second = 0.0;
        self.status = "Starting receiver…".to_owned();
    }
}

pub enum Action {
    OutputDirectorySelected(PathBuf),
    Start,
    Pause,
    Resume,
    Stop,
}

pub fn show(ui: &mut Ui, state: &mut ReceiverState, hardware: &HardwareSnapshot) -> Option<Action> {
    ui.heading("Receive Files");
    ui.label("Choose a destination and listen for a sender on the local network.");
    ui.add_space(8.0);

    let mut action = None;
    ui.horizontal(|ui| {
        if ui.button("Choose output folder…").clicked() {
            if let Some(path) = rfd::FileDialog::new().pick_folder() {
                action = Some(Action::OutputDirectorySelected(path));
            }
        }
        ui.label(
            state
                .output_directory
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "No folder selected".to_owned()),
        );
    });

    ui.horizontal(|ui| {
        ui.label("Listening port:");
        ui.text_edit_singleline(&mut state.port);
    });
    ui.colored_label(
        egui::Color32::from_rgb(120, 210, 150),
        "TLS 1.3 mutual certificate authentication is enabled; unknown devices require approval.",
    );

    let interface_names: Vec<String> = hardware
        .network
        .interfaces
        .iter()
        .filter(|interface| interface.usable_by_default)
        .map(|interface| interface.name.clone())
        .collect();
    if state.selected_interface.is_none() {
        state.selected_interface = interface_names.first().cloned();
    }
    ComboBox::from_label("Interface")
        .selected_text(
            state
                .selected_interface
                .as_deref()
                .unwrap_or("Automatic selection"),
        )
        .show_ui(ui, |ui| {
            for name in interface_names {
                ui.selectable_value(&mut state.selected_interface, Some(name.clone()), name);
            }
        });

    ui.separator();
    ui.label(egui::RichText::new("Detected receiver addresses").strong());
    Grid::new("receiver-addresses")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Interface");
            ui.label("Address");
            ui.label("Link");
            ui.label("Actions");
            ui.end_row();
            for interface in &hardware.network.interfaces {
                if !interface.usable_by_default {
                    continue;
                }
                let link = interface
                    .link_speed_mbps
                    .map(|speed| format!("{speed} Mbps"))
                    .unwrap_or_else(|| "unknown".to_owned());
                for address in interface.addresses() {
                    ui.label(&interface.name);
                    ui.monospace(address);
                    ui.label(&link);
                    let endpoint = format_endpoint(address, &state.port);
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(endpoint);
                    }
                    ui.end_row();
                }
            }
        });

    ui.add_space(10.0);
    ui.group(|ui| {
        ui.label(egui::RichText::new("Incoming transfers").strong());
        if state.running {
            ui.label(format!(
                "Listening on {}",
                state
                    .listening_address
                    .map(|address| address.to_string())
                    .unwrap_or_else(|| "starting…".to_owned())
            ));
            if state.total_bytes > 0 {
                let progress = state.bytes_transferred as f32 / state.total_bytes as f32;
                ui.add(egui::ProgressBar::new(progress.clamp(0.0, 1.0)).show_percentage());
                ui.label(format!(
                    "{} / {} · {} · {:.2} MB/s",
                    crate::hardware::format_bytes(state.bytes_transferred),
                    crate::hardware::format_bytes(state.total_bytes),
                    state.current_path,
                    state.speed_bytes_per_second / 1_048_576.0
                ));
            }
            ui.horizontal(|ui| {
                if state.paused {
                    if ui.button("Resume transfers").clicked() {
                        action = Some(Action::Resume);
                    }
                } else if ui.button("Pause transfers").clicked() {
                    action = Some(Action::Pause);
                }
                if ui.button("Stop listening").clicked() {
                    action = Some(Action::Stop);
                }
            });
        } else if ui
            .add_enabled(
                state.output_directory.is_some() && state.port.parse::<u16>().is_ok(),
                egui::Button::new("Start receiver"),
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

fn format_endpoint(address: &str, port: &str) -> String {
    if address.contains(':') {
        format!("[{address}]:{port}")
    } else {
        format!("{address}:{port}")
    }
}

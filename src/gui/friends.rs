use crate::storage::SavedFriend;
use egui::{Grid, Ui};

pub enum Action {
    Changed,
    Use {
        address: String,
        fingerprint: String,
    },
}

pub fn show(ui: &mut Ui, friends: &mut Vec<SavedFriend>) -> Option<Action> {
    ui.heading("Saved Friends");
    ui.label(
        "Trusted peers are persisted locally and keyed by device identity, not by IP address.",
    );
    ui.add_space(8.0);

    if friends.is_empty() {
        ui.group(|ui| {
            ui.label("No saved friends yet.");
            ui.label(
                "LAN discovery will add peers here; a first secure connection still requires explicit approval.",
            );
        });
        return None;
    }

    let mut remove = None;
    let mut use_friend = None;
    let mut changed = false;
    Grid::new("saved-friends")
        .num_columns(6)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Name");
            ui.label("Address");
            ui.label("OS");
            ui.label("Fingerprint");
            ui.label("Trust");
            ui.label("Actions");
            ui.end_row();
            for (index, friend) in friends.iter_mut().enumerate() {
                changed |= ui.text_edit_singleline(&mut friend.device_name).changed();
                let address = friend.display_address();
                ui.monospace(&address);
                ui.label(&friend.operating_system);
                ui.monospace(if friend.certificate_fingerprint.is_empty() {
                    "not enrolled"
                } else {
                    &friend.certificate_fingerprint
                });
                ui.label(if friend.trusted {
                    "trusted"
                } else {
                    "approval needed"
                });
                ui.horizontal(|ui| {
                    if ui.small_button("Copy").clicked() {
                        ui.ctx().copy_text(address.clone());
                    }
                    if ui
                        .add_enabled(
                            friend.last_known_ip.is_some() && friend.port != 0,
                            egui::Button::new("Use"),
                        )
                        .clicked()
                    {
                        use_friend =
                            Some((address.clone(), friend.certificate_fingerprint.clone()));
                    }
                    if ui.small_button("Remove").clicked() {
                        remove = Some(index);
                    }
                });
                ui.end_row();
            }
        });

    if let Some(index) = remove {
        friends.remove(index);
        return Some(Action::Changed);
    }
    if let Some((address, fingerprint)) = use_friend {
        return Some(Action::Use {
            address,
            fingerprint,
        });
    }
    changed.then_some(Action::Changed)
}

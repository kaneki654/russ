use crate::{
    core::BufferPlan,
    hardware::{format_bytes, HardwareSnapshot},
};
use egui::{Grid, Ui};

pub fn show(ui: &mut Ui, hardware: &HardwareSnapshot, plan: &BufferPlan) -> bool {
    let mut refresh = false;
    ui.heading("Dashboard");
    ui.label("Local resource profile used by the bounded transfer engine.");
    ui.add_space(8.0);

    ui.horizontal_wrapped(|ui| {
        metric(ui, "CPU", format!("{} logical", hardware.cpu.logical_cores));
        metric(
            ui,
            "RAM available",
            format_bytes(hardware.memory.available_bytes),
        );
        metric(ui, "Buffer", format_bytes(plan.buffer_size_bytes as u64));
        metric(
            ui,
            "In flight",
            format_bytes(plan.max_in_flight_bytes as u64),
        );
    });
    ui.add_space(10.0);

    ui.horizontal(|ui| {
        if ui.button("Refresh hardware").clicked() {
            refresh = true;
        }
        ui.label(format!(
            "Profile captured at Unix {}",
            hardware.captured_at_unix_seconds
        ));
    });

    ui.separator();
    ui.label(egui::RichText::new("System").strong());
    Grid::new("system-details")
        .num_columns(2)
        .striped(true)
        .show(ui, |ui| {
            row(ui, "Device", &hardware.hostname);
            row(
                ui,
                "Operating system",
                &format!("{} {}", hardware.operating_system, hardware.os_version),
            );
            row(ui, "Kernel", &hardware.kernel_version);
            row(
                ui,
                "CPU",
                &format!(
                    "{} ({} physical / {} logical)",
                    hardware.cpu.model, hardware.cpu.physical_cores, hardware.cpu.logical_cores
                ),
            );
            row(
                ui,
                "Architecture",
                &format!(
                    "{} · {} MHz average",
                    hardware.cpu.architecture, hardware.cpu.average_frequency_mhz
                ),
            );
            row(
                ui,
                "Memory",
                &format!(
                    "{} available / {} total",
                    format_bytes(hardware.memory.available_bytes),
                    format_bytes(hardware.memory.total_bytes)
                ),
            );
        });

    ui.add_space(10.0);
    ui.label(egui::RichText::new("Storage").strong());
    Grid::new("storage-details")
        .num_columns(3)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Mount");
            ui.label("Available");
            ui.label("Capacity");
            ui.end_row();
            for disk in &hardware.storage {
                ui.monospace(&disk.mount_point);
                ui.label(format_bytes(disk.available_bytes));
                ui.label(format_bytes(disk.total_bytes));
                ui.end_row();
            }
        });

    ui.add_space(10.0);
    ui.label(egui::RichText::new("Network interfaces").strong());
    Grid::new("network-details")
        .num_columns(4)
        .striped(true)
        .show(ui, |ui| {
            ui.label("Interface");
            ui.label("Addresses");
            ui.label("Link");
            ui.label("Default");
            ui.end_row();
            for interface in &hardware.network.interfaces {
                ui.label(&interface.name);
                ui.label(interface.addresses().collect::<Vec<_>>().join(", "));
                ui.label(
                    interface
                        .link_speed_mbps
                        .map(|speed| format!("{speed} Mbps"))
                        .unwrap_or_else(|| "unknown".to_owned()),
                );
                ui.label(if interface.usable_by_default {
                    "yes"
                } else {
                    "no"
                });
                ui.end_row();
            }
        });

    ui.add_space(10.0);
    ui.label(format!("Optimizer: {}", plan.reason));
    refresh
}

fn metric(ui: &mut Ui, title: &str, value: String) {
    ui.group(|ui| {
        ui.label(egui::RichText::new(title).small());
        ui.label(egui::RichText::new(value).size(18.0));
    });
}

fn row(ui: &mut Ui, key: &str, value: &str) {
    ui.strong(key);
    ui.label(value);
    ui.end_row();
}

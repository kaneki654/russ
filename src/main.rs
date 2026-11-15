use eframe::egui;

fn app_icon() -> egui::IconData {
    eframe::icon_data::from_png_bytes(include_bytes!("../assets/russ-logo.png"))
        .expect("embedded RUSS logo must be a valid PNG")
}

fn main() -> eframe::Result<()> {
    let arguments = std::env::args().collect::<Vec<_>>();
    if let Some(result) = russ::updater::internet::cli(&arguments) {
        match result {
            Ok(message) => println!("{message}"),
            Err(error) => {
                eprintln!("RUSS release command failed: {error:#}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--publish-updates")
    {
        if let Err(error) = std::env::current_dir()
            .map_err(anyhow::Error::from)
            .and_then(|workspace| russ::updater::publish_workspace_updates(&workspace))
        {
            eprintln!("RUSS update publication failed: {error:#}");
            std::process::exit(1);
        }
        println!("RUSS updates published. Keep RUSS open to announce and serve them on the LAN.");
        return Ok(());
    }
    if arguments
        .get(1)
        .is_some_and(|argument| argument == "--russ-update-helper")
    {
        if let Err(error) = russ::updater::run_helper_from_args(&arguments) {
            eprintln!("RUSS updater failed: {error:#}");
            std::process::exit(1);
        }
        return Ok(());
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("russ=info")),
        )
        .with_target(false)
        .compact()
        .init();

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1120.0, 780.0])
            .with_min_inner_size([860.0, 600.0])
            .with_icon(app_icon()),
        ..Default::default()
    };

    eframe::run_native(
        "RUSS — Rapid Universal Secure Sender",
        native_options,
        Box::new(|cc| Ok(Box::new(russ::app::RussApp::new(cc)))),
    )
}

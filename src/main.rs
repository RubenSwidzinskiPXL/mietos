mod agent;
mod app;
mod challenge;
mod events;
mod extract;
mod kali;
mod knowledge;
mod memory;
mod model;
mod osint;
mod planner;
mod playbooks;
mod runtime;
mod settings;
mod strategy;
mod thm;
mod tools;
mod workflows;

fn main() -> eframe::Result<()> {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1320.0, 860.0])
            .with_min_inner_size([980.0, 640.0]),
        ..Default::default()
    };

    eframe::run_native(
        "mietos",
        options,
        Box::new(|cc| Ok(Box::new(app::OperatorApp::new(cc)))),
    )
}

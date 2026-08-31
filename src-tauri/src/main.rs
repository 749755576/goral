#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    if let Some(exit_code) = netcatty_et::run_askpass_helper_if_requested() {
        std::process::exit(exit_code);
    }
    goral_desktop_lib::run();
}

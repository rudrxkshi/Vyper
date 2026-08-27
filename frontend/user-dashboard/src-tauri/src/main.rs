#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

fn main() {
    #[cfg(unix)]
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("VYPER Desktop GUI refuses to run as root.");
        std::process::exit(2);
    }
    tauri::Builder::default()
        .run(tauri::generate_context!())
        .expect("failed to run the VYPER desktop GUI");
}

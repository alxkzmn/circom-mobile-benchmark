use std::path::Path;

fn main() {
    witnesscalc_adapter::build_and_link("./test-vectors/circom");
    let udl_path = Path::new("src/mopro.udl");
    if !udl_path.exists() {
        std::fs::write(udl_path, mopro_ffi::app_config::UDL).expect("Failed to write UDL");
    }
    uniffi::generate_scaffolding(udl_path.to_str().unwrap()).unwrap();
}

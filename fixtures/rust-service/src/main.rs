//! Fixture service: reads an optional config file and prints a marker.
fn main() {
    let config = std::fs::read_to_string("config/service.yaml").ok();
    println!("rust-service started (config: {})", config.is_some());
}

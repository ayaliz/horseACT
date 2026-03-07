fn main() {
    println!("cargo:rerun-if-changed=.env");
    println!("cargo:rerun-if-env-changed=HORSEACT_HMAC_KEY");

    if let Ok(contents) = std::fs::read_to_string(".env") {
        for line in contents.lines() {
            let line = line.trim();
            if line.starts_with('#') || line.is_empty() {
                continue;
            }
            if let Some((key, val)) = line.split_once('=') {
                if key.trim() == "HORSEACT_HMAC_KEY" {
                    println!("cargo:rustc-env=HORSEACT_HMAC_KEY={}", val.trim());
                }
            }
        }
    }
}

fn main() {
    write_build_icon();
    if std::env::var_os("CARGO_CFG_TARGET_OS").as_deref() == Some("windows".as_ref()) {
        write_windows_icon().expect("Windows build icon cannot be generated");
    }
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "safe_create",
            "safe_open",
            "safe_unlock",
            "safe_list",
            "safe_import",
            "safe_export",
            "safe_create_directory",
            "safe_lock",
            "wallet_status",
            "wallet_access",
            "wallet_endpoint",
            "wallet_set_endpoint",
            "wallet_probe_endpoint",
            "wallet_refresh_directory",
            "wallet_send",
            "wallet_retry_payment",
        ]),
    ))
    .expect("desktop build configuration is invalid");
}

fn write_windows_icon() -> std::io::Result<()> {
    use std::fs::File;
    use std::io::BufReader;

    let image = ico::IconImage::read_png(BufReader::new(File::open("icons/icon.png")?))?;
    let mut icon = ico::IconDir::new(ico::ResourceType::Icon);
    icon.add_entry(ico::IconDirEntry::encode_as_bmp(&image)?);
    icon.write(File::create("icons/icon.ico")?)
}

fn write_build_icon() {
    const BRAND_ICON: &str = "../src/branding.local/siworld-icon-32.png";
    println!("cargo:rerun-if-changed=../src");
    std::fs::create_dir_all("icons").expect("icon directory cannot be created");
    if std::path::Path::new(BRAND_ICON).is_file() {
        std::fs::copy(BRAND_ICON, "icons/icon.png").expect("brand icon cannot be copied");
        return;
    }
    // Tauri requires a bitmap even for an unbundled executable.
    let mut pixels = vec![0_u8; 32 * 32 * 4];
    for y in 0..32 {
        for x in 0..32 {
            let index = (y * 32 + x) * 4;
            let lock = (10..22).contains(&x) && (15..25).contains(&y);
            let shackle =
                (10..22).contains(&x) && (7..16).contains(&y) && (!(13..19).contains(&x) || y < 10);
            let color = if lock || shackle {
                [237, 237, 237, 255]
            } else {
                [6, 6, 6, 255]
            };
            pixels[index..index + 4].copy_from_slice(&color);
        }
    }
    let file = std::fs::File::create("icons/icon.png").expect("build icon cannot be created");
    let mut encoder = png::Encoder::new(file, 32, 32);
    encoder.set_color(png::ColorType::Rgba);
    encoder.set_depth(png::BitDepth::Eight);
    encoder
        .write_header()
        .expect("icon header cannot be written")
        .write_image_data(&pixels)
        .expect("icon data cannot be written");
}

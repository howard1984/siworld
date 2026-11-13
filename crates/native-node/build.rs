fn main() {
    println!("cargo::rustc-check-cfg=cfg(siworld_native_node)");
    println!("cargo::rustc-cfg=siworld_native_node");
}

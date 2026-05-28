fn main() {
    // No special link flags for now; NDK toolchain handles everything.
    // arti-client + tor-rtcompat both compile cleanly against
    // aarch64-linux-android-clang when given a CC matching the NDK.
    println!("cargo:rerun-if-changed=src/");
}

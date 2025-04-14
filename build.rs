fn main() {
    #[cfg(not(target_os = "windows"))]
    println!("cargo:warning=This library is designed for Windows only.");
}

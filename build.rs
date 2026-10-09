// rcheevos (vendor/rcheevos, MIT) and the flat shim over it (src/ra/shim.c).
use std::path::Path;

fn main() {
    let rc = Path::new("vendor/rcheevos");
    let mut b = cc::Build::new();
    b.include(rc.join("include"))
        .include(rc.join("src"))
        .include(rc.join("src/api"))
        .include(rc.join("src/client"))
        .include(rc.join("src/runtime"))
        .include(rc.join("src/hash"))
        .include(rc.join("src/util"))
        .define("RC_NO_THREADS", None)
        .define("RC_HASH_NO_ENCRYPTED", None)
        .warnings(false);

    for dir in ["src/api", "src/runtime", "src/util", "src/hash"] {
        for entry in std::fs::read_dir(rc.join(dir)).unwrap() {
            let p = entry.unwrap().path();
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            // Encrypted 3DS hashing and the validator are not needed.
            if p.extension().is_some_and(|e| e == "c")
                && !matches!(name.as_str(), "rc_hash_encrypted.c" | "aes.c" | "rc_validate.c")
            {
                b.file(&p);
            }
        }
    }
    b.file(rc.join("src/client/rc_client.c"));
    b.file("src/ra/shim.c");
    b.compile("rcheevos");

    println!("cargo:rerun-if-changed=src/ra/shim.c");
    println!("cargo:rerun-if-changed=vendor/rcheevos");
    println!("cargo:rerun-if-changed=build.rs");
}

extern crate bindgen;
extern crate cc;

fn main() {
    let mut build = cc::Build::new();
    let tool = build.get_compiler();
    if tool.is_like_clang() || tool.is_like_gnu() {
        build
            .flag_if_supported("-msse4.1")
            .flag_if_supported("-maes");
    }

    build.warnings(false);
    build
        .file("ext/aesb.c")
        .file("ext/blake256.c")
        .file("ext/crypto-ops-data.c")
        .file("ext/crypto-ops.c")
        .file("ext/groestl.c")
        .file("ext/hash-extra-blake.c")
        .file("ext/hash-extra-groestl.c")
        .file("ext/hash-extra-jh.c")
        .file("ext/hash-extra-skein.c")
        .file("ext/hash.c")
        .file("ext/jh.c")
        .file("ext/chacha.c")
        .file("ext/keccak.c")
        .file("ext/oaes_lib.c")
        .file("ext/random.c")
        .file("ext/skein.c")
        .file("ext/slow-hash.c")
        .file("ext/tree-hash.c")
        .file("ext/crypto.c")
        .compile("crypto");
}
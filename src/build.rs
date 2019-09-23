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

    // build.warnings(false);
    build
        .define("__RUST_RAW_CRYPTO__", Some("1"))
        .file("ext/crypto/aesb.c")
        .file("ext/crypto/blake256.c")
        .file("ext/crypto/crypto-ops-data.c")
        .file("ext/crypto/crypto-ops.c")
        .file("ext/crypto/groestl.c")
        .file("ext/crypto/hash-extra-blake.c")
        .file("ext/crypto/hash-extra-groestl.c")
        .file("ext/crypto/hash-extra-jh.c")
        .file("ext/crypto/hash-extra-skein.c")
        .file("ext/crypto/hash.c")
        .file("ext/crypto/jh.c")
        .file("ext/crypto/chacha.c")
        .file("ext/crypto/keccak.c")
        .file("ext/crypto/oaes_lib.c")
        .file("ext/crypto/random.c")
        .file("ext/crypto/skein.c")
        .file("ext/crypto/slow-hash.c")
        .file("ext/crypto/tree-hash.c")
        .file("ext/crypto/crypto.c")
        .compile("crypto");
    let mut buildcpp = cc::Build::new();
    buildcpp.cpp(true);
    buildcpp
    .flag("-std=c++11")
    .include("ext/")
    .file("ext/cryptonote/core/difficulty.cpp")
    .file("ext/util/vec_pub.cpp")
    .file("ext/util/vec_signature.cpp")
    .compile("vec");
}
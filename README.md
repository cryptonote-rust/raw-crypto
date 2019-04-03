# raw-crypto Library For CryptoNote Based Crypto Currencies


[![](https://travis-ci.com/cryptonote-rust/raw-crypto.svg?branch=master)](https://travis-ci.com/cryptonote-rust/raw-crypto)
[![](https://img.shields.io/crates/v/cryptonote-raw-crypto.svg)](https://crates.io/crates/cryptonote-raw-crypto)
[![codecov](https://codecov.io/gh/cryptonote-rust/raw-crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptonote-rust/raw-crypto)



# Usage


```
    // Generate key
    let key = ChachaKey::generate(String::from(""));

    // Generate iv
    let iv = ChachaIV::from([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);

    // Generate chacha object
    let chacha = Chacha::new(key, iv);

    // Prepare plain text
    let plain = *b"hello world!";

    // Encrypt with chacha8
    let cipher = chacha.encrypt(&plain[..]);

    // Encrypt again will get the original plain text
    let recipher = chacha.encrypt(&cipher[..]);

    // they should be equal
    assert!(plain == recipher.as_slice());
```
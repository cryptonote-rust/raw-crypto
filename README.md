# raw-crypto Library For CryptoNote Based Crypto Currencies


[![](https://travis-ci.com/cryptonote-rust/raw-crypto.svg?branch=master)](https://travis-ci.com/cryptonote-rust/raw-crypto)
[![](https://img.shields.io/crates/v/cryptonote-raw-crypto.svg)](https://crates.io/crates/cryptonote-raw-crypto)
[![codecov](https://codecov.io/gh/cryptonote-rust/raw-crypto/branch/master/graph/badge.svg)](https://codecov.io/gh/cryptonote-rust/raw-crypto)


# Intro

Raw Crypto Library is to provide crypto implementations in C/C++ with rust. Currently the library has implemented all hash functions provided by the cryptonote foundation in it's referential coin forging code base.

Now this library provide the follow interfaces:

1. Hash  
Hash::slow -> cn_slow_hash  
Hash::fast -> cn_fast_hash  
Hash::check_with_difficulty -> cryptonote::check_hash

2. Chacha(with ChachaKey, ChachaIV generators)  
Chacha::generate -> chacha8  

3. Key  
Key::generate_private_key -> generate_private_key  
Key::secret_to_public -> secret_key_to_public_key  
Key::generate_key_pair -> generate_keys  
Key::check_public_key -> check_public_key  
Key::generate_key_derivation -> generate_key_derivation  
Key::derive_public_key -> derive_public_key  
Key::underive_public_key -> underive_public_key  
Key::derive_secret_key -> derive_secret_key  
Key::generate_signature -> generate_signature  
Key::check_signature -> check_signature  
Key::generate_key_image -> generate_key_image  

4. Ring  
Ring::generate_signature -> generate_ring_signature
Ring::check_signature -> check_ring_signature

5. Scalars  
EllipticCurveScalar::random -> random_scalar  
EllipticCurveScalar::check -> check_scalar  
EllipticCurveScalar::to_hash -> hash_to_scalar  
EllipticCurveScalar::from_hash -> hash_to_ec  
EllipticCurvePoint::from_hash -> hash_to_point  

# Usage

Usage can be found in tests.

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
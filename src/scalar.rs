extern "C" {
  fn check_scalar(scalar: *const u8) -> bool;
  fn random_scalar(secret_key: *mut u8);
  fn hash_to_scalar(data: *const u8, length: usize, hash: *mut u8);
  fn hash_to_point(hash: *const u8, point: *mut u8);
  fn hash_to_ec_ex(hash: *const u8, ec: *mut u8);
}

pub struct EllipticCurveScalar {}

pub struct EllipticCurvePoint {}

impl EllipticCurveScalar {
  pub fn check(scalar: &[u8; 32]) -> bool {
    unsafe { return check_scalar(scalar[..].as_ptr()) }
  }

  pub fn random(secret_key: &mut [u8; 32]) {
    unsafe {
      random_scalar(secret_key.as_mut_ptr());
    }
  }
  pub fn to_hash(scalar: &[u8]) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    unsafe { hash_to_scalar(scalar.as_ptr(), scalar.len(), hash.as_mut_ptr()) }
    hash
  }

  pub fn from_hash(hash: &[u8]) -> [u8; 32] {
    let mut ec: [u8; 32] = [0; 32];
    unsafe { hash_to_ec_ex(hash.as_ptr(), ec.as_mut_ptr()) }
    ec
  }
}

impl EllipticCurvePoint {
  pub fn from_hash(hash: &[u8]) -> [u8; 32] {
    let mut point: [u8; 32] = [0; 32];
    unsafe {
      hash_to_point(hash.as_ptr(), point.as_mut_ptr());
    }
    point
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::{canonicalize, File};
  use std::io::{prelude::*, BufReader};
  use std::path::PathBuf;
  extern crate hex;
  use super::super::key::Key;
  use super::super::ring::Ring;

  extern "C" {
    fn setup_random(value: i32);
  }

  fn to_fixed_32(variant: Vec<u8>) -> [u8; 32] {
    let mut fixed: [u8; 32] = [0; 32];
    for i in 0..32 {
      fixed[i] = variant[i];
    }
    fixed
  }

  fn to_fixed_64(variant: Vec<u8>) -> [u8; 64] {
    let mut fixed: [u8; 64] = [0; 64];
    for i in 0..64 {
      fixed[i] = variant[i];
    }
    fixed
  }

  #[test]
  fn should_to_hash() {
    let bytes = hex::decode("2ace").expect("Error parse scalar");
    let hash = EllipticCurveScalar::to_hash(bytes.as_slice());
    let expected = hex::decode("427f5090283713a2a8448285f2a22cc8cf5374845766b6370425e2319e40f50d")
      .expect("Error parse scalar");
    assert!(hash == expected.as_slice());
  }

  #[test]
  fn should_test_scalar() {
    let path = PathBuf::from("./tests/tests.txt");
    let str = canonicalize(path);
    let f = File::open(str.unwrap()).unwrap();
    let file = BufReader::new(&f);
    let mut last = String::from("");
    let mut executed = false;
    for (_num, line) in file.lines().enumerate() {
      let l = line.unwrap();
      let split: Vec<&str> = l.split_whitespace().collect();
      let name = split[0];
      if last != name {
        last = split[0].to_string();
      }
      match name {
        "check_scalar" => {
          let plain = hex::decode(split[1]).expect("Error parse scalar");
          let expected = split[2] == String::from("true");
          let mut scalar: [u8; 32] = [0; 32];
          for i in 0..32 {
            scalar[i] = plain[i];
          }
          let actual = EllipticCurveScalar::check(&scalar);
          assert!(expected == actual)
        }
        "random_scalar" => {
          if !executed {
            unsafe {
              setup_random(42);
            }
            executed = true;
          }
          let expected = hex::decode(split[1]).expect("Error parse expected");
          let mut ec_scalar: [u8; 32] = [0; 32];
          EllipticCurveScalar::random(&mut ec_scalar);
          for i in 0..32 {
            assert!(expected[i] == ec_scalar[i]);
          }
        }
        "hash_to_scalar" => {
          let mut bytes: Vec<u8>;
          if split[1] == "x" {
            bytes = hex::decode("").expect("Error parse scalar");
          } else {
            bytes = hex::decode(split[1]).expect("Error parse scalar");
          }
          let hash = EllipticCurveScalar::to_hash(bytes.as_slice());
          let expected = hex::decode(split[2]).expect("Error parse expected");
          assert!(hash == expected.as_slice());
        }
        "generate_keys" => {
          let public_key = hex::decode(split[1]).expect("Error parse expected");
          let private_key = hex::decode(split[2]).expect("Error parse expected");
          let mut generated_public_key: [u8; 32] = [0; 32];
          let mut generated_private_key: [u8; 32] = [0; 32];
          Key::generate_key_pair(&mut generated_public_key, &mut generated_private_key);
          assert!(public_key.as_slice() == generated_public_key);
          assert!(private_key.as_slice() == generated_private_key);
        }
        "check_key" => {
          let public_key = hex::decode(split[1]).expect("Error parse expected");
          assert!(public_key.len() == 32);
          let mut fixed_public_key: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_public_key[i] = public_key[i];
          }
          let expected = split[2] == "true";
          assert!(Key::check_public_key(&fixed_public_key) == expected);
        }
        "secret_key_to_public_key" => {
          let secret_key = hex::decode(split[1]).expect("Error parse expected");
          let mut fixed_secret_key: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_secret_key[i] = secret_key[i];
          }
          let expected1 = split[2] == "true";
          let mut public_key: [u8; 32] = [0; 32];
          let actual1 = Key::secret_to_public(&fixed_secret_key, &mut public_key);
          assert!(expected1 == actual1);
          if expected1 == true {
            let expected2 = hex::decode(split[3]).expect("Error parse expected");
            assert!(public_key == expected2.as_slice());
          }
        }
        "generate_key_derivation" => {
          let public_key = hex::decode(split[1]).expect("Error parse expected");
          let mut fixed_public_key: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_public_key[i] = public_key[i];
          }
          let secret_key = hex::decode(split[2]).expect("Error parse expected");
          let mut fixed_secret_key: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_secret_key[i] = secret_key[i];
          }
          let expected1 = split[3] == "true";
          let derived = Key::generate_key_derivation(&fixed_public_key, &fixed_secret_key);
          if expected1 {
            let expected2 = hex::decode(split[4]).expect("Error parse expected");
            assert!(derived == expected2.as_slice());
          } else {
            assert!(derived == [0; 32]);
          }
        }
        "derive_public_key" => {
          let derivation = hex::decode(split[1]).expect("Error parse derivation");
          let out_index = split[2].parse::<u32>().unwrap();
          let public_key = hex::decode(split[3]).expect("Error parse public key");
          let expected1 = split[4] == "true";
          let mut fixed_derivation: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_derivation[i] = derivation[i];
          }

          let mut fixed_base: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_base[i] = public_key[i];
          }
          let derived = Key::derive_public_key(&fixed_derivation, out_index as u64, &fixed_base);

          if expected1 {
            let expected2 = hex::decode(split[5]).expect("Error parse expected derived");
            assert!(expected2.as_slice() == derived);
          } else {
            assert!(derived == [0; 32]);
          }
        }
        "derive_secret_key" => {
          let derivation = hex::decode(split[1]).expect("Error parse derivation");
          let out_index = split[2].parse::<u32>().unwrap();

          let private_key = hex::decode(split[3]).expect("Error parse public key");
          let expected = hex::decode(split[4]).expect("Error parse public key");
          let mut fixed_derivation: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_derivation[i] = derivation[i];
          }

          let mut fixed_base: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_base[i] = private_key[i];
          }
          let derived = Key::derive_secret_key(&fixed_derivation, out_index as u64, &fixed_base);
          assert!(derived == expected.as_slice());
        }
        "underive_public_key" => {
          let derivation = hex::decode(split[1]).expect("Error parse derivation");
          let out_index = split[2].parse::<u32>().unwrap();
          let public_key = hex::decode(split[3]).expect("Error parse public key");
          let expected1 = split[4] == "true";
          let mut fixed_derivation: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_derivation[i] = derivation[i];
          }

          let mut fixed_base: [u8; 32] = [0; 32];
          for i in 0..32 {
            fixed_base[i] = public_key[i];
          }
          let derived = Key::underive_public_key(&fixed_derivation, out_index as u64, &fixed_base);

          if expected1 {
            let expected2 = hex::decode(split[5]).expect("Error parse expected derived");
            assert!(expected2.as_slice() == derived);
          } else {
            assert!(derived == [0; 32]);
          }
        }
        "generate_signature" => {
          let prefix_hash = hex::decode(split[1]).expect("Error parse prefix hash");
          let public_key = hex::decode(split[2]).expect("Error parse public key");
          let secret_key = hex::decode(split[3]).expect("Error parse secret key");
          let expected = hex::decode(split[4]).expect("Error parse expected signature");

          let actual = Key::generate_signature(
            &to_fixed_32(prefix_hash),
            &to_fixed_32(public_key),
            &to_fixed_32(secret_key),
          );
          for i in 0..64 {
            assert!(expected[i] == actual[i]);
          }
        }
        "check_signature" => {
          let prefix_hash = hex::decode(split[1]).expect("Error parse prefix hash");
          let public_key = hex::decode(split[2]).expect("Error parse public key");
          let signature = hex::decode(split[3]).expect("Error parse secret key");
          let expected = split[4] == "true";

          let actual = Key::check_signature(
            &to_fixed_32(prefix_hash),
            &to_fixed_32(public_key),
            &to_fixed_64(signature),
          );
          assert!(expected == actual);
        }
        "hash_to_point" => {
          let hash = hex::decode(split[1]).expect("Error parse prefix hash");
          let expected = hex::decode(split[2]).expect("Error parse public key");
          let actual = EllipticCurvePoint::from_hash(hash.as_slice());
          assert!(expected == actual);
        }
        "hash_to_ec" => {
          let public_key = hex::decode(split[1]).expect("Error parse prefix hash");
          let expected = hex::decode(split[2]).expect("Error parse public key");
          let actual = EllipticCurveScalar::from_hash(public_key.as_slice());
          assert!(expected == actual);
        }
        "generate_key_image" => {
          let public_key = hex::decode(split[1]).expect("Error parse prefix hash");
          let secret_key = hex::decode(split[2]).expect("Error parse public key");
          let expected = hex::decode(split[3]).expect("Error parse public key");
          let actual = Key::generate_key_image(&to_fixed_32(public_key), &to_fixed_32(secret_key));
          assert!(expected == actual);
        }
        "generate_ring_signature" => {
          let prefix_hash = hex::decode(split[1]).expect("Error parse prefix hash");
          let image = hex::decode(split[2]).expect("Error parse key image");
          let pubs_count = split[3].parse::<usize>().unwrap();

          let mut pubsv: Vec<[u8; 32]> = vec![];
          for i in 0..pubs_count {
            let public_key = hex::decode(split[(4 + i)]).expect("Error parse public key");
            let fixed = to_fixed_32(public_key);
            pubsv.push(fixed);
          }
          let secret_key = hex::decode(split[(4 + pubs_count)]).expect("Error parse secret key");
          let secret_index = split[(5 + pubs_count)].parse::<usize>().unwrap();
          let expected = hex::decode(split[(6 + pubs_count)]).expect("Error parse signatures");
          let actual = Ring::generate_signature(
            &to_fixed_32(prefix_hash),
            &to_fixed_32(image),
            &pubsv,
            pubs_count,
            &to_fixed_32(secret_key),
            secret_index,
          );
          assert!(expected == actual);
        }
        "check_ring_signature" => {
          let prefix_hash = hex::decode(split[1]).expect("Error parse prefix hash");
          let image = hex::decode(split[2]).expect("Error parse key image");
          let pubs_count = split[3].parse::<usize>().unwrap();

          let mut pubsv: Vec<[u8; 32]> = vec![];
          for i in 0..pubs_count {
            let public_key = hex::decode(split[(4 + i)]).expect("Error parse public key");
            let fixed = to_fixed_32(public_key);
            pubsv.push(fixed);
          }
          let signatures = hex::decode(split[(4 + pubs_count)]).expect("Error parse secret key");
          let expected = split[(5 + pubs_count)] == "true";
          println!("{:x?}", split);
          if (expected) {
          let actual = Ring::check_signature(
            &to_fixed_32(prefix_hash),
            &to_fixed_32(image),
            &pubsv,
            pubs_count,
            &signatures
          );
          }
          // assert!(expected == actual);
        }
        _ => {}
      }
    }
  }
}

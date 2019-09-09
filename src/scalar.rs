use super::consts::*;

extern "C" {
  fn setup_random(value: i32);
  fn check_scalar(scalar: *const u8) -> bool;
  fn random_scalar(secret_key: *mut u8);
  fn hash_to_scalar(data: *const u8, length: usize, res: *mut u8);
}

pub struct EllipticCurveScalar {
  pub data: [u8; CHACHA_IV_SIZE],
}

impl EllipticCurveScalar {
  pub fn check(scalar: [u8; 32]) -> bool {
    unsafe { return check_scalar(scalar[..].as_ptr()) }
  }

  pub fn random(secret_key: &mut [u8; 32]) {
    unsafe {
      random_scalar(secret_key.as_mut_ptr());
    }
  }

  pub fn from(plain: &String) -> [u8; 32] {
    let mut scalar: [u8; 32] = [0; 32];
    unsafe { hash_to_scalar(plain.as_ptr(), plain.len(), scalar[..].as_mut_ptr()) }
    scalar
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::fs::{self, canonicalize, File};
  use std::io::{self, prelude::*, BufReader};
  use std::path::PathBuf;
  extern crate hex;

  #[test]
  fn should_test_scalar() {
    let path = PathBuf::from("./tests/tests.txt");
    let str = canonicalize(path);
    println!("{:?}", &str);
    let f = File::open(str.unwrap()).unwrap();
    let file = BufReader::new(&f);
    let mut last = String::from("");
    let mut executed = false;
    for (num, line) in file.lines().enumerate() {
      let l = line.unwrap();
      let split: Vec<&str> = l.split_whitespace().collect();
      let name = split[0];
      if last != name {
        println!("{:?}", split[0]);
        last = split[0].to_string();
      }
      match name {
        "check_scalar" => {
          println!("{:x?}", split);
          let plain = hex::decode(split[1]).expect("Error parse scalar");
          let expected = split[2] == String::from("true");
          let mut scalar: [u8; 32] = [0; 32];
          for i in 0..32 {
            scalar[i] = plain[i];
          }
          let actual = EllipticCurveScalar::check(scalar);
          assert!(expected == actual)
        }
        "hash_to_scalar" => {
          // println!("{:x?}", split);
          // let plain = split[1];
          // let expected = hex::decode(split[2]).expect("Error parse expected");
          // println!("palin = {}", plain);
          // println!("expected = {:x?}", expected);
          // let mut data: [u8; 32] = [0; 32];
          // scalar_hash(&String::from(plain), &mut data[..]);
          // assert_eq!(data, expected[..]);
        }
        "random_scalar" => {
          if !executed {
            unsafe {
              setup_random(42);
            }
            executed = true;
          }
          // println!("{:x?}", split);
          let expected = hex::decode(split[1]).expect("Error parse expected");
          println!("{:x?}", expected);
          let mut ec_scalar: [u8; 32] = [0; 32];
          EllipticCurveScalar::random(&mut ec_scalar);
          println!("{:x?}", ec_scalar);
          // let expected = hex::decode(split[1]).expect("Error parse expected");
          // println!("{:x?}", expected);
          for i in 0..32 {
            assert!(expected[i] == ec_scalar[i]);
          }
        }
        "check_ring_signature" => {
          let pre_hash = hex::decode(split[1]).expect("Error parse pre hash!");
          // println!("pre hash = {}", split[1]);
          let key_image = hex::decode(split[2]).expect("Error parse key image!");
          // println!("key image = {}", split[2]);

          let pubs_count = split[3].parse::<u64>().expect("Error parse integer!");
          // println!("pubs count = {}", split[3]);

          let mut pubs: Vec<u8> = vec![];
          for n in 0..pubs_count {
            // println!("{}", n);
            // println!("{}", split[4 + n as usize]);
            let key = hex::decode(split[4 + n as usize]).expect("Error parse public key!");
            // println!("{:x?}", key);

            let mut converted_key: [u8; 32] = [0; 32];
            for i in 0..32 {
              // pubs.push(key[i]);
              converted_key[i] = key[i];
            }
            // println!("n = {}", n);
            // println!("n = {:x?}", converted_key);
            pubs.extend(&converted_key);
          }

          // println!("pubs.len() = {}", pubs.len());
          // println!("{}", 32 * pubs_count);

          // assert!(pubs.len() == (32 * pubs_count) as usize);

          // let sig = hex::decode(split[4 + pubs_count as usize]).expect("Error parse siginatures!");
          // println!("{}", sig.len());
          // println!("{}", pubs_count);
          // let mut siginatures : Vec<[u8; 64]> = vec![];
          // for n in 0..pubs_count {
          //   let mut n_sig : [u8;64] = [0; 64];
          //   for i in 0..64 {
          //     let idx = n * 64 + (i as u64);
          //     n_sig[i] = sig[idx as usize];
          //   }
          //   siginatures
          // }

          // println!("{:?}", split);
          // let expected = split[5 + pubs_count as usize] == "true";
          // println!("expected = {}", expected);
          // let actual = is_ring_signature(pre_hash.as_slice(), key_image.as_slice(), pubs.as_slice(), pubs_count as usize, sig.as_slice());
          // assert!(expected == actual);
        }
        _ => {}
      }
    }
  }
}

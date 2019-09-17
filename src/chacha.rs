
use super::consts::*;
use super::hash::Hash;
use rand::Rng;

extern "C" {
  fn chacha8(data: *const u8, length: usize, key: *const u8, iv: *const u8, cipher: *mut u8);
}

pub struct ChachaKey {
  pub data: [u8; CHACHA_KEY_SIZE],
}

pub struct ChachaIV {
  pub data: [u8; CHACHA_IV_SIZE],
}

pub struct Chacha {
  pub key: ChachaKey,
  pub iv: ChachaIV,
}

impl ChachaIV {
  pub fn new() -> ChachaIV {
    let mut rng = rand::thread_rng();
    let mut data: [u8; CHACHA_IV_SIZE] = [0; CHACHA_IV_SIZE];
    for x in &mut data {
      *x = rng.gen();
    }
    ChachaIV { data }
  }
  pub fn from(data: [u8; CHACHA_IV_SIZE]) -> ChachaIV {
    ChachaIV { data }
  }
}

impl Chacha {
  pub fn new(key: ChachaKey, iv: ChachaIV) -> Chacha {
    Chacha { key, iv }
  }
  pub fn encrypt(&self, plain: &[u8]) -> Vec<u8> {
    return Chacha::generate(self.key.data, self.iv.data, plain);
  }

  pub fn generate(key: [u8; 32], iv: [u8; 8], plain: &[u8]) -> Vec<u8> {
    let mut cipher = vec![0; plain.len()];
    unsafe {
      chacha8(
        plain.as_ptr(),
        plain.len(),
        key.as_ptr(),
        iv.as_ptr(),
        cipher.as_mut_ptr(),
      );
    }
    cipher
  }
}

impl ChachaKey {
  pub fn generate(password: String) -> ChachaKey {
    let data = Hash::slow(&password.into_bytes());
    ChachaKey { data }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  extern crate hex;

  #[test]
  fn should_generate_key_and_cipher_contents() {
    let key = ChachaKey::generate(String::from(""));
    // println!("key {:?}", key.data);
    assert!(
      key.data
        == [
          235, 20, 232, 168, 51, 250, 198, 254, 154, 67, 181, 123, 51, 103, 137, 196, 111, 254,
          147, 242, 134, 132, 82, 36, 7, 32, 96, 123, 20, 56, 126, 17
        ]
    );

    let key1 = ChachaKey::generate(String::from("This is a test"));
    // println!("key {:?}", key1.data);

    // assert!(key1.data == [97, 48, 56, 52, 102, 48, 49, 100, 49, 52, 51, 55, 97, 48, 57, 99, 54, 57, 56, 53, 52, 48, 49, 98, 54, 48, 100, 52, 51, 53, 53, 52]);
    assert!(
      key1.data
        == [
          160, 132, 240, 29, 20, 55, 160, 156, 105, 133, 64, 27, 96, 212, 53, 84, 174, 16, 88, 2,
          197, 245, 216, 169, 179, 37, 54, 73, 192, 190, 102, 5
        ]
    );

    let _iv = ChachaIV::new();
    let iv = ChachaIV::from([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    let chacha = Chacha::new(key, iv);
    let plain = *b"hello world!";
    let cipher = chacha.encrypt(&plain[..]);
    let cipher1 = chacha.encrypt(&cipher[..]);
    assert!(plain == cipher1.as_slice());
  }
}
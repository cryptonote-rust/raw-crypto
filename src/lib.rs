use rand::Rng;

const CHACHA_KEY_SIZE: usize = 32;
const CHACHA_IV_SIZE: usize = 8;

extern "C" {
  fn chacha8(data: *const u8, length: usize, key: *const u8, iv: *const u8, cipher: *mut u8);
  fn cn_slow_hash(data: *const u8, length: usize, hash: *mut u8, variant: usize, prehashed: usize);

}

pub struct ChachaKey {
  pub data: [u8; CHACHA_KEY_SIZE],
}

pub type Hash = ChachaKey;

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
    let mut cipher = vec![0; plain.len()];
    unsafe {
      chacha8(
        plain.as_ptr(),
        plain.len(),
        self.key.data.as_ptr(),
        self.iv.data.as_ptr(),
        cipher.as_mut_ptr(),
      );
    }
    cipher
  }
}

impl ChachaKey {
  pub fn generate(password: String) -> ChachaKey {
    let input = password.as_bytes();
    let mut data: [u8; CHACHA_KEY_SIZE] = [0; CHACHA_KEY_SIZE];
    unsafe {
      cn_slow_hash(input.as_ptr(), input.len(), data.as_mut_ptr(), 0, 0);
    }
    ChachaKey { data }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn should_generate_key_and_cipher_contents() {
    let key = ChachaKey::generate(String::from(""));
    println!("key {:?}", key.data);
    // assert!(key.data == [101, 98, 49, 52, 101, 56, 97, 56, 51, 51, 102, 97, 99, 54, 102, 101, 57, 97, 52, 51, 98, 53, 55, 98, 51, 51, 54, 55, 56, 57, 99, 52]);
    
    assert!(key.data == [235, 20, 232, 168, 51, 250, 198, 254, 154, 67, 181, 123, 51, 103, 137, 196, 111, 254, 147, 242, 134, 132, 82, 36, 7, 32, 96, 123, 20, 56, 126, 17]);
    
    let key1 = ChachaKey::generate(String::from("This is a test"));
    println!("key {:?}", key1.data);

    // assert!(key1.data == [97, 48, 56, 52, 102, 48, 49, 100, 49, 52, 51, 55, 97, 48, 57, 99, 54, 57, 56, 53, 52, 48, 49, 98, 54, 48, 100, 52, 51, 53, 53, 52]);
    assert!(key1.data == [160, 132, 240, 29, 20, 55, 160, 156, 105, 133, 64, 27, 96, 212, 53, 84, 174, 16, 88, 2, 197, 245, 216, 169, 179, 37, 54, 73, 192, 190, 102, 5]);

    let _iv = ChachaIV::new();
    let iv = ChachaIV::from([0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18]);
    let chacha = Chacha::new(key, iv);
    let plain = *b"hello world!";
    let cipher = chacha.encrypt(&plain[..]);
    let cipher1 = chacha.encrypt(&cipher[..]);
    assert!(plain == cipher1.as_slice());
  }
}

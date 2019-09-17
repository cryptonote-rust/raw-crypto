use super::scalar::EllipticCurveScalar;

extern "C" {
  fn generate_keys(public: *mut u8, secret: *mut u8);
  fn check_public_key(public_key: *const u8) -> bool;
  fn secret_key_to_public_key(secret_key: *const u8, public_key: *mut u8) -> bool;
  fn generate_key_derivation(
    public_key: *const u8,
    secret_key: *const u8,
    derivation: *mut u8,
  ) -> bool;
  fn derive_public_key(
    derivation: *const u8,
    output_index: u64,
    base_public_key: *const u8,
    derived_key: *mut u8,
  ) -> bool;
  fn underive_public_key(
    derivation: *const u8,
    output_index: u64,
    base_public_key: *const u8,
    derived_key: *mut u8,
  ) -> bool;
  fn derive_secret_key(
    derivation: *const u8,
    output_index: u64,
    base_secret_key: *const u8,
    derived_key: *mut u8,
  ) -> bool;

  fn generate_signature(
    prefix_hash: *const u8,
    public_key: *const u8,
    secret_key: *const u8,
    signature: *mut u8,
  );

  fn check_signature(prefix_hash: *const u8, public_key: *const u8, signature: *const u8) -> bool;

  fn generate_key_image(public_key: *const u8, secret_key: *const u8, image: *mut u8);
}

pub struct Key {}

impl Key {
  pub fn generate_key_pair(public_key: &mut [u8; 32], secret_key: &mut [u8; 32]) {
    unsafe { generate_keys(public_key.as_mut_ptr(), secret_key.as_mut_ptr()) }
  }

  pub fn generate_secret_key() -> [u8; 32] {
    let mut secret_key: [u8; 32] = [0; 32];
    EllipticCurveScalar::random(&mut secret_key);
    secret_key
  }

  pub fn check_public_key(public_key: &[u8; 32]) -> bool {
    unsafe { return check_public_key(public_key.as_ptr()) }
  }
  pub fn secret_to_public(secret_key: &[u8; 32], public_key: &mut [u8; 32]) -> bool {
    unsafe { return secret_key_to_public_key(secret_key.as_ptr(), public_key.as_mut_ptr()) }
  }
  pub fn generate_key_derivation(public_key: &[u8; 32], secret_key: &[u8; 32]) -> [u8; 32] {
    let mut derived: [u8; 32] = [0; 32];
    unsafe {
      generate_key_derivation(
        public_key.as_ptr(),
        secret_key.as_ptr(),
        derived.as_mut_ptr(),
      );
    }
    derived
  }
  pub fn derive_public_key(
    derivation: &[u8; 32],
    output_index: u64,
    base_public_key: &[u8; 32],
  ) -> [u8; 32] {
    let mut derived: [u8; 32] = [0; 32];
    unsafe {
      derive_public_key(
        derivation.as_ptr(),
        output_index,
        base_public_key.as_ptr(),
        derived.as_mut_ptr(),
      );
    }
    derived
  }

  pub fn underive_public_key(
    derivation: &[u8; 32],
    output_index: u64,
    base_public_key: &[u8; 32],
  ) -> [u8; 32] {
    let mut derived: [u8; 32] = [0; 32];
    unsafe {
      underive_public_key(
        derivation.as_ptr(),
        output_index,
        base_public_key.as_ptr(),
        derived.as_mut_ptr(),
      );
    }
    derived
  }
  pub fn derive_secret_key(
    derivation: &[u8; 32],
    output_index: u64,
    base_secret_key: &[u8; 32],
  ) -> [u8; 32] {
    let mut derived: [u8; 32] = [0; 32];
    unsafe {
      derive_secret_key(
        derivation.as_ptr(),
        output_index,
        base_secret_key.as_ptr(),
        derived.as_mut_ptr(),
      );
    }
    derived
  }

  pub fn generate_signature(
    prefix_hash: &[u8; 32],
    public_key: &[u8; 32],
    secret_key: &[u8; 32],
  ) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    unsafe {
      generate_signature(
        prefix_hash.as_ptr(),
        public_key.as_ptr(),
        secret_key.as_ptr(),
        signature.as_mut_ptr(),
      );
    }
    signature
  }

  pub fn check_signature(
    prefix_hash: &[u8; 32],
    public_key: &[u8; 32],
    signature: &[u8; 64],
  ) -> bool {
    unsafe {
      return check_signature(
        prefix_hash.as_ptr(),
        public_key.as_ptr(),
        signature.as_ptr(),
      );
    }
  }

  pub fn generate_key_image(public_key: &[u8; 32], secret_key: &[u8; 32]) -> [u8; 32] {
    let mut image: [u8; 32] = [0; 32];
    unsafe {
      generate_key_image(public_key.as_ptr(), secret_key.as_ptr(), image.as_mut_ptr());
    }
    image
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn should_get_public_key_from_secret_key() {
    let secret_key = [
      50, 228, 229, 247, 39, 151, 194, 252, 14, 45, 218, 78, 128, 230, 27, 208, 9, 57, 52, 163, 5,
      175, 8, 201, 211, 185, 66, 113, 88, 68, 170, 8,
    ];
    let mut public_key: [u8; 32] = [0; 32];
    Key::secret_to_public(&secret_key, &mut public_key);
    // println!("{:?}", public_key);
    // println!("{:?}", public_key);
    assert!(
      public_key
        == [
          81, 76, 248, 201, 237, 192, 109, 39, 58, 159, 67, 13, 120, 203, 91, 70, 36, 216, 162,
          222, 0, 100, 243, 152, 32, 48, 89, 129, 252, 169, 180, 36
        ]
    );
    assert!(Key::check_public_key(&public_key));
  }

  #[test]
  fn should_get_public_key_from_generated_secret_key() {
    let secret_key = Key::generate_secret_key();
    let mut public_key: [u8; 32] = [0; 32];
    Key::secret_to_public(&secret_key, &mut public_key);
    // println!("{:?}", secret_key);
    // println!("{:?}", public_key);
    assert!(public_key.len() == 32);
    assert!(Key::check_public_key(&public_key));
  }
}

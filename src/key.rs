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
}
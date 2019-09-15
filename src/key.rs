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
  fn generate_ring_signature(
    prefix_hash: *const u8,
    image: *const u8,
    pubs: *const &[u8;32],
    pubs_count: usize,
    sec: *const u8,
    sec_index: usize,
    sig: *const u8,
  );
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

  pub fn generate_ring_signature(
    prefix_hash: &[u8; 32],
    image: &[u8; 32],
    pubs: &Vec<&[u8; 32]>,
    pubs_count: usize,
    sec: &[u8; 32],
    sec_index: usize,
  ) -> [u8; 64] {
    let mut signature: [u8; 64] = [0; 64];
    unsafe {
      generate_ring_signature(
        prefix_hash.as_ptr(),
        image.as_ptr(),
        pubs.as_ptr(),
        pubs_count,
        sec.as_ptr(),
        sec_index,
        signature.as_mut_ptr(),
      )
    }
    signature
  }
}

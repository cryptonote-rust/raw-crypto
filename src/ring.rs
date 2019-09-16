extern "C" {
  fn vec_resize(size: usize);
  fn vec_clear();
  fn vec_push(i: usize, key: *const u8);
  fn vec_data() -> *const *const u8;

  fn sig_resize(size: usize);
  fn sig_clear();
  fn sig_push(i: usize, key: *const u8);
  fn sig_data() -> *const u8;
  fn generate_ring_signature(
    prefix_hash: *const u8,
    image: *const u8,
    pubs: *const *const u8,
    pubs_count: usize,
    sec: *const u8,
    sec_index: usize,
    sig: *const u8,
  );

  fn check_ring_signature(
    prefix_hash: *const u8,
    image: *const u8,
    pubs: *const *const u8,
    pubs_count: usize,
    sig: *const u8,
  ) -> bool;
}

pub struct Ring {}

impl Ring {
  pub fn generate_signature(
    prefix_hash: &[u8; 32],
    image: &[u8; 32],
    pubs: &Vec<[u8; 32]>,
    pubs_count: usize,
    sec: &[u8; 32],
    sec_index: usize,
  ) -> Vec<u8> {
    let mut signature: Vec<u8> = vec![0; pubs_count * 64];
    unsafe {
      vec_clear();
      vec_resize(pubs.len());
      for i in 0..pubs.len() {
        vec_push(i, pubs[i].as_ptr());
      }
      generate_ring_signature(
        prefix_hash.as_ptr(),
        image.as_ptr(),
        vec_data(),
        pubs_count,
        sec.as_ptr(),
        sec_index,
        signature.as_mut_ptr(),
      );
      vec_clear();
    }
    signature
  }
  pub fn check_signature(
    prefix_hash: &[u8; 32],
    image: &[u8; 32],
    pubs: &Vec<[u8; 32]>,
    pubs_count: usize,
    signatures: &Vec<u8>,
  ) -> bool {
    let result: bool;
    unsafe {
      assert!(signatures.len() == 64 * pubs_count);
      sig_clear();
      sig_resize(pubs.len());
      for i in 0..pubs.len() {
        let mut sign: [u8; 64] = [0; 64];
        for j in 0..64 {
          sign[j] = signatures[i * 64 + j];
        }
        println!("{:x?}", sign.as_ptr());
        sig_push(i, sign.as_ptr());
      }
      vec_clear();
      vec_resize(pubs.len());
      for i in 0..pubs.len() {
        vec_push(i, pubs[i].as_ptr());
      }
      result = check_ring_signature(
        prefix_hash.as_ptr(),
        image.as_ptr(),
        vec_data(),
        pubs_count,
        sig_data(),
      );
      vec_clear();
      sig_clear();
    }
    result
  }
}

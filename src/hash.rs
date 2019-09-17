extern "C" {
  fn cn_slow_hash(data: *const u8, length: usize, hash: *mut u8, variant: usize, prehashed: usize);
  fn cn_fast_hash(data: *const u8, length: usize, hash: *mut u8);
}

pub struct Hash {}

impl Hash {
  pub fn fast(data: &[u8]) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    unsafe { cn_fast_hash(data.as_ptr(), data.len(), hash.as_mut_ptr()) }
    hash
  }
  pub fn slow(input: &Vec<u8>) -> [u8; 32] {
    let mut hash: [u8; 32] = [0; 32];
    unsafe {
      cn_slow_hash(input.as_ptr(), input.len(), hash.as_mut_ptr(), 0, 0);
    }
    hash
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn should_get_fast_hash() {
    let input = [
      0x01, 0x3c, 0x01, 0xff, 0x00, 0x01, 0x01, 0x02, 0x9b, 0x2e, 0x4c, 0x02, 0x81, 0xc0, 0xb0,
      0x2e, 0x7c, 0x53, 0x29, 0x1a, 0x94, 0xd1, 0xd0, 0xcb, 0xff, 0x88, 0x83, 0xf8, 0x02, 0x4f,
      0x51, 0x42, 0xee, 0x49, 0x4f, 0xfb, 0xbd, 0x08, 0x80, 0x71, 0x21, 0x01, 0xa9, 0xa4, 0x56,
      0x9f, 0x7e, 0x10, 0x16, 0x4a, 0x32, 0x32, 0x4b, 0x2b, 0x87, 0x8a, 0xe3, 0x2d, 0x98, 0xbe,
      0x09, 0x49, 0xce, 0x6e, 0x01, 0x50, 0xba, 0x1d, 0x7e, 0x54, 0xd6, 0x09, 0x69, 0xe5,
    ];
    let hash = Hash::fast(&input);
    assert!(
      hash
        == [
          81, 131, 30, 137, 17, 68, 149, 122, 23, 4, 105, 195, 35, 123, 221, 255, 230, 192, 96, 73,
          129, 38, 117, 210, 237, 178, 168, 52, 82, 247, 162, 80
        ]
    );
    let input = [
      50, 228, 229, 247, 39, 151, 194, 252, 14, 45, 218, 78, 128, 230, 27, 208, 9, 57, 52, 163, 5,
      175, 8, 201, 211, 185, 66, 113, 88, 68, 170, 8,
    ];
    let hash = Hash::fast(&input);
    assert!(
      hash
        == [
          197, 173, 69, 56, 117, 95, 205, 188, 226, 116, 198, 205, 121, 235, 248, 74, 211, 46, 177,
          65, 72, 147, 115, 194, 212, 214, 163, 109, 121, 3, 36, 249
        ]
    );
    let input = [50];
    let hash = Hash::fast(&input);
    assert!(
      hash
        == [
          173, 124, 91, 239, 2, 120, 22, 168, 0, 218, 23, 54, 68, 79, 181, 138, 128, 126, 244, 201,
          96, 59, 120, 72, 103, 63, 126, 58, 104, 235, 20, 165
        ]
    );
  }
}

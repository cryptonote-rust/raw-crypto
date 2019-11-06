extern "C" {

  fn get_penalized_amount(amount: u64, median_size: usize, current_block_size: usize) -> u64;
}

pub struct Amount {}

impl Amount {
  pub fn get_penalized(amount: u64, median_size: usize, current_block_size: usize) -> u64 {
    unsafe {
      return get_penalized_amount(amount, median_size, current_block_size);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  // use std::cmp;
  // use std::fs::{canonicalize, File};
  // use std::io::{prelude::*, BufReader};
  // use std::path::PathBuf;

  #[test]
  fn should_test_amount() {
    assert!(0 == Amount::get_penalized(0, 1, 2));
    assert!(2 == Amount::get_penalized(2, 1, 1));
    assert!(7 == Amount::get_penalized(10, 1000, 1500));
    assert!(1 == Amount::get_penalized(2, 10, 11));
  }
}

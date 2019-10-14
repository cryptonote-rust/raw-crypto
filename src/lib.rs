pub mod chacha;
pub mod consts;
pub mod hash;
pub mod key;
pub mod ring;
pub mod scalar;

extern "C" {
  fn next_difficulty(
    timestamps: *mut u64,
    timestamps_length: u16,
    cumulative_difficulties: *const u64,
    difficulties_length: u16,
    difficulty_config: *const u64,
  ) -> u64;
}

#[repr(C)]
pub struct Difficulty {
  target: u8,  // seconds
  cut: u8,     //  timestamps to cut after sorting
  lag: u16,    //
  window: u32, // expected numbers of blocks per day
}

impl From<&Difficulty> for u64 {
  fn from(data: &Difficulty) -> Self {
    let mut ret: u64;
    ret = (data.window as u64) << 32;
    ret += (data.lag as u64) << 16;
    ret += (data.cut as u64) << 8;
    ret += data.target as u64;
    ret
  }
}

impl Difficulty {
  pub fn next(&self, timestamps: &mut [u64], cumulative_difficulties: &[u64]) -> u64 {
    unsafe {
      let value = u64::from(self);
      return next_difficulty(
        timestamps.as_mut_ptr(),
        timestamps.len() as u16,
        cumulative_difficulties.as_ptr(),
        cumulative_difficulties.len() as u16,
        &value as *const u64,
      );
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::cmp;
  use std::fs::{canonicalize, File};
  use std::io::{prelude::*, BufReader};
  use std::path::PathBuf;

  #[test]
  fn should_test_difficulty() {
    let diff = Difficulty {
      target: 120,
      window: 720,
      cut: 60,
      lag: 15,
    };
    let path = PathBuf::from("./tests/difficulty.txt");
    let str = canonicalize(path);
    let f = File::open(str.unwrap()).unwrap();
    let file = BufReader::new(&f);
    let mut n: u64 = 0;
    let mut timestamps: Vec<u64> = Vec::with_capacity(1);
    let mut cumulative_difficulties: Vec<u64> = Vec::with_capacity(1);
    let mut cumulative_difficulty: u64 = 0;
    for (_num, line) in file.lines().enumerate() {
      let l = line.unwrap();
      let split: Vec<&str> = l.split_whitespace().collect();
      let timestamp = split[0].parse::<u64>().unwrap();
      let difficulty = split[1].parse::<u64>().unwrap();
      let begin: usize;
      let end: usize;
      let window = diff.window.clone();
      let lag = diff.lag.clone();
      if n < (window + lag as u32) as u64 {
        begin = 0;
        end = cmp::min(n as usize, window as usize);
      } else {
        end = n as usize - lag as usize;
        begin = end - window as usize;
      }
      let mut ts : Vec<u64> = vec![];
      for i in begin..end {
        ts.push(timestamps[i]);
      }
      let res: u64 = diff.next(
        &mut ts[0..],
        &cumulative_difficulties[begin..end],
      );
      assert!(res == difficulty);
      timestamps.push(timestamp);
      cumulative_difficulty += difficulty;
      cumulative_difficulties.push(cumulative_difficulty);

      n += 1;
    }
  }
}

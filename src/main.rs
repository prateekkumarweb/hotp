use hmac::{Hmac, Mac, NewMac};
use sha1::Sha1;
use std::time::{SystemTime, UNIX_EPOCH};

fn decode(code: u8) -> u8 {
    match code.to_ascii_uppercase() {
        b'A'..=b'Z' => code - b'A',
        b'2'..=b'7' => code - b'2' + 26,
        _ => panic!("Incorrect code"),
    }
}

fn parse_key(key: &str) -> Vec<u8> {
    let mut buffer: u64 = 0;
    let mut bits_left = 0;
    let mut result = vec![];
    let key = key
        .as_bytes()
        .iter()
        .filter(|&c| *c != b' ')
        .map(|&c| decode(c));
    for c in key {
        buffer <<= 5;
        buffer |= (c & 31) as u64;
        bits_left += 5;
        if bits_left >= 8 {
            result.push((buffer >> (bits_left - 8)) as u8);
            bits_left -= 8;
        }
    }
    result
}

fn truncate(hash: &[u8]) -> u64 {
    let offset = (hash[19] & 0xf) as usize;
    let truncated: u64 = (hash[offset] as u64 & 0x7f) << 24
        | (hash[offset + 1] as u64 & 0xff) << 16
        | (hash[offset + 2] as u64 & 0xff) << 8
        | (hash[offset + 3] as u64 & 0xff);
    truncated % 1_000_000
}

pub fn run() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let key = parse_key("aaaa bbbb cccc xxxx yyyy zzzz 2222 7777");
    let mut hmac = Hmac::<Sha1>::new_varkey(&key).unwrap();
    hmac.update(&(now / 30).to_be_bytes());
    let otp = truncate(&hmac.finalize().into_bytes());
    format!("{:03} {:03} {}", otp / 1000, otp % 1000, 30 - now % 30)
}

fn main() {
    println!("{}", run());
}

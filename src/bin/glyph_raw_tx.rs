use std::env;

use glyph::adapters::keccak256;
use rlp::RlpStream;
use secp256k1::{ecdsa::RecoverableSignature, Message, Secp256k1, SecretKey};

fn main() {
    let args: Vec<String> = env::args().collect();

    let mut to: Option<[u8; 20]> = None;
    let mut data: Vec<u8> = Vec::new();
    let mut chain_id: Option<u64> = None;
    let mut nonce: Option<u64> = None;
    let mut gas_price: Option<u128> = None;
    let mut gas_limit: Option<u64> = None;
    let mut value: u128 = 0;
    let mut private_key: Option<[u8; 32]> = None;
    let mut json = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--to" => {
                i += 1;
                to = Some(parse_addr20(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--data" => {
                i += 1;
                data = parse_hex_bytes(args.get(i).map(|s| s.as_str()).unwrap_or(""));
            }
            "--chain-id" => {
                i += 1;
                chain_id = Some(parse_u64(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--nonce" => {
                i += 1;
                nonce = Some(parse_u64(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--gas-price" => {
                i += 1;
                gas_price = Some(parse_u128(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--gas-limit" => {
                i += 1;
                gas_limit = Some(parse_u64(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--value" => {
                i += 1;
                value = parse_u128(args.get(i).map(|s| s.as_str()).unwrap_or(""));
            }
            "--private-key" => {
                i += 1;
                private_key = Some(parse_bytes32(args.get(i).map(|s| s.as_str()).unwrap_or("")));
            }
            "--json" => json = true,
            _ => {
                die(&format!("unknown argument: {}", args[i]));
            }
        }
        i += 1;
    }

    let to = to.unwrap_or_else(|| die("missing --to"));
    let chain_id = chain_id.unwrap_or_else(|| die("missing --chain-id"));
    let nonce = nonce.unwrap_or_else(|| die("missing --nonce"));
    let gas_price = gas_price.unwrap_or_else(|| die("missing --gas-price"));
    let gas_limit = gas_limit.unwrap_or_else(|| die("missing --gas-limit"));
    let private_key = private_key.unwrap_or_else(|| die("missing --private-key"));

    let unsigned = rlp_unsigned(nonce, gas_price, gas_limit, &to, value, &data, chain_id);
    let sighash = keccak256(&unsigned);

    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&private_key).unwrap_or_else(|_| die("invalid private key"));
    let msg = Message::from_digest_slice(&sighash).unwrap_or_else(|_| die("invalid sighash"));
    let sig = secp.sign_ecdsa_recoverable(&msg, &sk);
    let (recid, sig_bytes) = sig.serialize_compact();

    let v: u64 = recid.to_i32() as u64 + 35 + chain_id * 2;
    let r = trim_leading_zeros(&sig_bytes[0..32]);
    let s = trim_leading_zeros(&sig_bytes[32..64]);
    let raw = rlp_signed(nonce, gas_price, gas_limit, &to, value, &data, v, &r, &s);
    let raw_hex = format!("0x{}", hex::encode(&raw));
    let tx_hash = format!("0x{}", hex::encode(keccak256(&raw)));

    if json {
        println!(
            "{{\"raw_tx\":\"{}\",\"tx_hash\":\"{}\",\"chain_id\":{},\"nonce\":{},\"gas_price\":{},\"gas_limit\":{},\"to\":\"0x{}\",\"value\":{},\"data_len\":{}}}",
            raw_hex,
            tx_hash,
            chain_id,
            nonce,
            gas_price,
            gas_limit,
            hex::encode(to),
            value,
            data.len()
        );
    } else {
        println!("{}", raw_hex);
    }
}

fn rlp_unsigned(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    chain_id: u64,
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    rlp_append_u64(&mut stream, nonce);
    rlp_append_u128(&mut stream, gas_price);
    rlp_append_u64(&mut stream, gas_limit);
    stream.append(&to.as_slice());
    rlp_append_u128(&mut stream, value);
    stream.append(&data);
    rlp_append_u64(&mut stream, chain_id);
    rlp_append_u8(&mut stream, 0);
    rlp_append_u8(&mut stream, 0);
    stream.out().to_vec()
}

fn rlp_signed(
    nonce: u64,
    gas_price: u128,
    gas_limit: u64,
    to: &[u8; 20],
    value: u128,
    data: &[u8],
    v: u64,
    r: &[u8],
    s: &[u8],
) -> Vec<u8> {
    let mut stream = RlpStream::new_list(9);
    rlp_append_u64(&mut stream, nonce);
    rlp_append_u128(&mut stream, gas_price);
    rlp_append_u64(&mut stream, gas_limit);
    stream.append(&to.as_slice());
    rlp_append_u128(&mut stream, value);
    stream.append(&data);
    rlp_append_u64(&mut stream, v);
    stream.append(&r);
    stream.append(&s);
    stream.out().to_vec()
}

fn rlp_append_u8(stream: &mut RlpStream, value: u8) {
    rlp_append_u128(stream, value as u128);
}

fn rlp_append_u64(stream: &mut RlpStream, value: u64) {
    rlp_append_u128(stream, value as u128);
}

fn rlp_append_u128(stream: &mut RlpStream, value: u128) {
    let bytes = u128_to_min_bytes(value);
    stream.append(&bytes);
}

fn u128_to_min_bytes(value: u128) -> Vec<u8> {
    if value == 0 {
        return Vec::new();
    }
    let bytes = value.to_be_bytes();
    let idx = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[idx..].to_vec()
}

fn trim_leading_zeros(bytes: &[u8]) -> Vec<u8> {
    let idx = bytes.iter().position(|b| *b != 0).unwrap_or(bytes.len());
    bytes[idx..].to_vec()
}

fn parse_u64(text: &str) -> u64 {
    if let Some(hex) = text.strip_prefix("0x") {
        u64::from_str_radix(hex, 16).unwrap_or_else(|_| die("invalid u64 hex value"))
    } else {
        text.parse::<u64>().unwrap_or_else(|_| die("invalid u64 value"))
    }
}

fn parse_u128(text: &str) -> u128 {
    if let Some(hex) = text.strip_prefix("0x") {
        u128::from_str_radix(hex, 16).unwrap_or_else(|_| die("invalid u128 hex value"))
    } else {
        text.parse::<u128>().unwrap_or_else(|_| die("invalid u128 value"))
    }
}

fn parse_addr20(text: &str) -> [u8; 20] {
    let bytes = parse_hex_fixed(text, 20);
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    out
}

fn parse_bytes32(text: &str) -> [u8; 32] {
    let bytes = parse_hex_fixed(text, 32);
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    out
}

fn parse_hex_bytes(text: &str) -> Vec<u8> {
    if text.is_empty() {
        return Vec::new();
    }
    let stripped = text.strip_prefix("0x").unwrap_or(text);
    if stripped.is_empty() {
        return Vec::new();
    }
    hex::decode(stripped).unwrap_or_else(|_| die("invalid hex bytes"))
}

fn parse_hex_fixed(text: &str, len: usize) -> Vec<u8> {
    let bytes = parse_hex_bytes(text);
    if bytes.len() != len {
        die(&format!("expected {} bytes, got {}", len, bytes.len()));
    }
    bytes
}

fn die(msg: &str) -> ! {
    eprintln!("ERROR: {}", msg);
    std::process::exit(1);
}

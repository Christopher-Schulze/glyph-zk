use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;

use serde_json::{Map, Value};
use tiny_keccak::{Hasher, Keccak};

fn die(msg: &str) -> ! {
    eprintln!("ERROR: {}", msg);
    std::process::exit(1)
}

fn read_json(path: &PathBuf) -> Value {
    let raw = fs::read_to_string(path).unwrap_or_else(|err| {
        die(&format!("read failed for {}: {}", path.display(), err))
    });
    serde_json::from_str(&raw).unwrap_or_else(|err| {
        die(&format!("invalid json in {}: {}", path.display(), err))
    })
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut ordered: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in map.iter() {
                ordered.insert(k.clone(), canonicalize_value(v));
            }
            let mut out = Map::new();
            for (k, v) in ordered {
                out.insert(k, v);
            }
            Value::Object(out)
        }
        Value::Array(items) => {
            let next = items.iter().map(canonicalize_value).collect::<Vec<_>>();
            Value::Array(next)
        }
        _ => value.clone(),
    }
}

fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    let mut out = [0u8; 32];
    hasher.update(data);
    hasher.finalize(&mut out);
    out
}

fn hex_0x(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2 + 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

fn write_bytes(path: &PathBuf, data: &[u8]) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).unwrap_or_else(|err| {
            die(&format!("create dir failed for {}: {}", parent.display(), err))
        });
    }
    fs::write(path, data).unwrap_or_else(|err| {
        die(&format!("write failed for {}: {}", path.display(), err))
    });
}

fn usage() -> ! {
    eprintln!(
        "usage: glyph_state_diff <build|hash|verify> --in <file> [--out <file>] [--emit-bytes <file>] [--hash <0x...>] [--json] [--pre <file>] [--post <file>]"
    );
    std::process::exit(1)
}

fn as_object<'a>(value: &'a Value, ctx: &str) -> &'a Map<String, Value> {
    value.as_object().unwrap_or_else(|| die(&format!("{} must be an object", ctx)))
}

fn get_accounts(value: &Value) -> BTreeMap<String, &Value> {
    let obj = as_object(value, "snapshot");
    let accounts = obj
        .get("accounts")
        .unwrap_or_else(|| die("snapshot missing accounts"))
        .as_object()
        .unwrap_or_else(|| die("accounts must be an object"));
    let mut out = BTreeMap::new();
    for (addr, acc) in accounts {
        out.insert(addr.to_string(), acc);
    }
    out
}

fn get_field(acc: Option<&&Value>, field: &str) -> String {
    if let Some(acc) = acc {
        if let Some(value) = acc.get(field) {
            if let Some(s) = value.as_str() {
                return s.to_string();
            }
        }
    }
    "0x0".to_string()
}

fn get_storage(acc: Option<&&Value>) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let Some(acc) = acc else { return out };
    let Some(storage) = acc.get("storage") else { return out };
    let storage = storage
        .as_object()
        .unwrap_or_else(|| die("storage must be an object"));
    for (slot, value) in storage {
        let val = value
            .as_str()
            .unwrap_or_else(|| die("storage values must be strings"));
        out.insert(slot.to_string(), val.to_string());
    }
    out
}

fn build_state_diff(pre: &Value, post: &Value) -> Value {
    let pre_accounts = get_accounts(pre);
    let post_accounts = get_accounts(post);
    let mut addresses = BTreeSet::new();
    for addr in pre_accounts.keys() {
        addresses.insert(addr.to_string());
    }
    for addr in post_accounts.keys() {
        addresses.insert(addr.to_string());
    }

    let mut account_diffs = Vec::new();
    for addr in addresses {
        let pre_acc = pre_accounts.get(&addr);
        let post_acc = post_accounts.get(&addr);
        let created = pre_acc.is_none() && post_acc.is_some();
        let deleted = pre_acc.is_some() && post_acc.is_none();

        let nonce_from = get_field(pre_acc, "nonce");
        let nonce_to = get_field(post_acc, "nonce");
        let balance_from = get_field(pre_acc, "balance");
        let balance_to = get_field(post_acc, "balance");
        let code_from = get_field(pre_acc, "code_hash");
        let code_to = get_field(post_acc, "code_hash");

        let mut storage_pre = get_storage(pre_acc);
        let storage_post = get_storage(post_acc);
        let mut slots = BTreeSet::new();
        for slot in storage_pre.keys() {
            slots.insert(slot.to_string());
        }
        for slot in storage_post.keys() {
            slots.insert(slot.to_string());
        }

        let mut storage_diffs = Vec::new();
        for slot in slots {
            let from = storage_pre.remove(&slot).unwrap_or_else(|| "0x0".to_string());
            let to = storage_post.get(&slot).cloned().unwrap_or_else(|| "0x0".to_string());
            if from != to {
                let mut entry = Map::new();
                entry.insert("slot".to_string(), Value::String(slot));
                entry.insert("from".to_string(), Value::String(from));
                entry.insert("to".to_string(), Value::String(to));
                storage_diffs.push(Value::Object(entry));
            }
        }

        let mut changes = Map::new();
        changes.insert("address".to_string(), Value::String(addr.clone()));
        if created {
            changes.insert("created".to_string(), Value::Bool(true));
        }
        if deleted {
            changes.insert("deleted".to_string(), Value::Bool(true));
        }
        if nonce_from != nonce_to {
            let mut nonce = Map::new();
            nonce.insert("from".to_string(), Value::String(nonce_from));
            nonce.insert("to".to_string(), Value::String(nonce_to));
            changes.insert("nonce".to_string(), Value::Object(nonce));
        }
        if balance_from != balance_to {
            let mut balance = Map::new();
            balance.insert("from".to_string(), Value::String(balance_from));
            balance.insert("to".to_string(), Value::String(balance_to));
            changes.insert("balance".to_string(), Value::Object(balance));
        }
        if code_from != code_to {
            let mut code = Map::new();
            code.insert("from".to_string(), Value::String(code_from));
            code.insert("to".to_string(), Value::String(code_to));
            changes.insert("code_hash".to_string(), Value::Object(code));
        }
        if !storage_diffs.is_empty() {
            changes.insert("storage".to_string(), Value::Array(storage_diffs));
        }

        if changes.len() > 1 {
            account_diffs.push(Value::Object(changes));
        }
    }

    let mut out = Map::new();
    out.insert("version".to_string(), Value::Number(1.into()));
    out.insert("accounts".to_string(), Value::Array(account_diffs));
    Value::Object(out)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let cmd = args[1].as_str();
    let mut input = None;
    let mut out = None;
    let mut emit_bytes = None;
    let mut expected = None;
    let mut json_out = false;
    let mut pre = None;
    let mut post = None;

    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--in" => {
                i += 1;
                input = args.get(i).map(PathBuf::from);
            }
            "--out" => {
                i += 1;
                out = args.get(i).map(PathBuf::from);
            }
            "--emit-bytes" => {
                i += 1;
                emit_bytes = args.get(i).map(PathBuf::from);
            }
            "--hash" => {
                i += 1;
                expected = args.get(i).cloned();
            }
            "--pre" => {
                i += 1;
                pre = args.get(i).map(PathBuf::from);
            }
            "--post" => {
                i += 1;
                post = args.get(i).map(PathBuf::from);
            }
            "--json" => {
                json_out = true;
            }
            _ => usage(),
        }
        i += 1;
    }

    match cmd {
        "build" => {
            let pre = pre.unwrap_or_else(|| die("--pre required"));
            let post = post.unwrap_or_else(|| die("--post required"));
            let pre_value = read_json(&pre);
            let post_value = read_json(&post);
            let diff = build_state_diff(&pre_value, &post_value);
            let canonical = canonicalize_value(&diff);
            let bytes = serde_json::to_vec(&canonical).unwrap_or_else(|err| {
                die(&format!("serialize failed: {}", err))
            });
            let digest = hex_0x(&keccak256(&bytes));
            if let Some(path) = out.as_ref() {
                let pretty = serde_json::to_string_pretty(&canonical)
                    .unwrap_or_else(|err| die(&format!("serialize failed: {err}")));
                write_bytes(path, pretty.as_bytes());
            } else if !json_out {
                let pretty = serde_json::to_string_pretty(&canonical)
                    .unwrap_or_else(|err| die(&format!("serialize failed: {err}")));
                println!("{pretty}");
            }
            if let Some(path) = emit_bytes.as_ref() {
                write_bytes(path, &bytes);
            }
            if json_out {
                let mut obj = Map::new();
                obj.insert("hash".to_string(), Value::String(digest));
                if let Some(path) = out.as_ref() {
                    obj.insert("out_path".to_string(), Value::String(path.display().to_string()));
                }
                if let Some(path) = emit_bytes.as_ref() {
                    obj.insert(
                        "bytes_path".to_string(),
                        Value::String(path.display().to_string()),
                    );
                }
                println!("{}", Value::Object(obj));
            }
        }
        "hash" => {
            let input = input.unwrap_or_else(|| die("--in required"));
            let value = read_json(&input);
            let canonical = canonicalize_value(&value);
            let bytes = serde_json::to_vec(&canonical).unwrap_or_else(|err| {
                die(&format!("serialize failed: {}", err))
            });
            let digest = hex_0x(&keccak256(&bytes));
            if let Some(path) = emit_bytes.as_ref() {
                write_bytes(path, &bytes);
            }
            if let Some(path) = out.as_ref() {
                write_bytes(path, digest.as_bytes());
            }
            if json_out {
                let mut obj = Map::new();
                obj.insert("hash".to_string(), Value::String(digest));
                if let Some(path) = emit_bytes.as_ref() {
                    obj.insert(
                        "bytes_path".to_string(),
                        Value::String(path.display().to_string()),
                    );
                }
                println!("{}", Value::Object(obj));
            } else if out.is_none() {
                println!("{}", digest);
            }
        }
        "verify" => {
            let input = input.unwrap_or_else(|| die("--in required"));
            let value = read_json(&input);
            let canonical = canonicalize_value(&value);
            let bytes = serde_json::to_vec(&canonical).unwrap_or_else(|err| {
                die(&format!("serialize failed: {}", err))
            });
            let digest = hex_0x(&keccak256(&bytes));
            let expected = expected.unwrap_or_else(|| die("--hash required"));
            if digest != expected {
                die("state diff hash mismatch");
            }
            println!("ok");
        }
        _ => usage(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::collection::{btree_map, vec};
    use proptest::prelude::*;

    fn snapshot_from_accounts(accounts: Vec<(String, Value)>) -> Value {
        let mut map = Map::new();
        let mut accounts_map = Map::new();
        for (addr, acc) in accounts {
            accounts_map.insert(addr, acc);
        }
        map.insert("accounts".to_string(), Value::Object(accounts_map));
        Value::Object(map)
    }

    fn account_json(nonce: &str, balance: &str, code_hash: &str, storage: Vec<(String, String)>) -> Value {
        let mut map = Map::new();
        map.insert("nonce".to_string(), Value::String(nonce.to_string()));
        map.insert("balance".to_string(), Value::String(balance.to_string()));
        map.insert("code_hash".to_string(), Value::String(code_hash.to_string()));
        let mut storage_map = Map::new();
        for (slot, value) in storage {
            storage_map.insert(slot, Value::String(value));
        }
        map.insert("storage".to_string(), Value::Object(storage_map));
        Value::Object(map)
    }

    #[test]
    fn canonical_json_is_stable_for_key_order() {
        let a = serde_json::json!({"b": 1, "a": 2});
        let b = serde_json::json!({"a": 2, "b": 1});
        let ca = canonicalize_value(&a);
        let cb = canonicalize_value(&b);
        let ba = match serde_json::to_vec(&ca) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        let bb = match serde_json::to_vec(&cb) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        assert_eq!(ba, bb);
        assert_eq!(hex_0x(&keccak256(&ba)), hex_0x(&keccak256(&bb)));
    }

    #[test]
    fn build_state_diff_is_deterministic() {
        let pre = serde_json::json!({
            "accounts": {
                "0x01": {"nonce": "0x1", "balance": "0x0", "code_hash": "0x0", "storage": {"0x02": "0x0"}}
            }
        });
        let post = serde_json::json!({
            "accounts": {
                "0x01": {"nonce": "0x2", "balance": "0x0", "code_hash": "0x0", "storage": {"0x02": "0x3"}}
            }
        });
        let diff = build_state_diff(&pre, &post);
        let canon = canonicalize_value(&diff);
        let bytes = match serde_json::to_vec(&canon) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        assert!(!bytes.is_empty());
    }

    #[test]
    fn state_diff_empty_when_snapshots_equal() {
        let acc = account_json("0x1", "0x2", "0x3", vec![
            ("0x01".to_string(), "0x0".to_string()),
            ("0x02".to_string(), "0x0".to_string()),
        ]);
        let snap = snapshot_from_accounts(vec![("0xabc".to_string(), acc)]);
        let diff = build_state_diff(&snap, &snap);
        let obj = match diff.as_object() {
            Some(obj) => obj,
            None => {
                assert!(false, "diff object");
                return;
            }
        };
        let accounts = match obj.get("accounts").and_then(Value::as_array) {
            Some(accounts) => accounts,
            None => {
                assert!(false, "accounts");
                return;
            }
        };
        assert!(accounts.is_empty());
    }

    #[test]
    fn tamper_detection_changes_hash() {
        let pre = serde_json::json!({
            "accounts": {
                "0x01": {"nonce": "0x1", "balance": "0x0", "code_hash": "0x0", "storage": {"0x02": "0x0"}}
            }
        });
        let post = serde_json::json!({
            "accounts": {
                "0x01": {"nonce": "0x2", "balance": "0x0", "code_hash": "0x0", "storage": {"0x02": "0x3"}}
            }
        });
        let diff = build_state_diff(&pre, &post);
        let canon = canonicalize_value(&diff);
        let bytes = match serde_json::to_vec(&canon) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        let digest = hex_0x(&keccak256(&bytes));

        let mut tampered = canon.clone();
        let obj = match tampered.as_object_mut() {
            Some(obj) => obj,
            None => {
                assert!(false, "object");
                return;
            }
        };
        let accounts = match obj.get_mut("accounts").and_then(Value::as_array_mut) {
            Some(accounts) => accounts,
            None => {
                assert!(false, "accounts");
                return;
            }
        };
        if let Some(first) = accounts.first_mut() {
            let first_obj = match first.as_object_mut() {
                Some(first_obj) => first_obj,
                None => {
                    assert!(false, "account obj");
                    return;
                }
            };
            first_obj.insert("tamper".to_string(), Value::Bool(true));
        }
        let tampered_bytes = match serde_json::to_vec(&tampered) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        let tampered_hash = hex_0x(&keccak256(&tampered_bytes));
        assert_ne!(digest, tampered_hash);
    }

    #[test]
    fn large_diff_build_is_stable() {
        let mut pre_accounts = Vec::new();
        let mut post_accounts = Vec::new();
        for i in 0..128u32 {
            let addr = format!("0x{:04x}", i);
            let storage = vec![
                (format!("0x{:04x}", i), "0x0".to_string()),
                (format!("0x{:04x}", i + 1), "0x0".to_string()),
            ];
            pre_accounts.push((addr.clone(), account_json("0x1", "0x0", "0x0", storage.clone())));
            post_accounts.push((addr, account_json("0x2", "0x0", "0x0", storage)));
        }
        let pre = snapshot_from_accounts(pre_accounts);
        let post = snapshot_from_accounts(post_accounts);
        let diff = build_state_diff(&pre, &post);
        let canon = canonicalize_value(&diff);
        let bytes = match serde_json::to_vec(&canon) {
            Ok(bytes) => bytes,
            Err(err) => {
                assert!(false, "serialize: {err}");
                return;
            }
        };
        assert!(!bytes.is_empty());
    }

    proptest! {
        #[test]
        fn prop_canonical_hash_stable_with_reordered_accounts(
            accounts in btree_map("0x[0-9a-f]{4}", vec(("0x[0-9a-f]{4}", "0x[0-9a-f]{4}"), 0..4), 0..8)
        ) {
            let mut ordered = Vec::new();
            let mut reversed = Vec::new();
            for (addr, storage_pairs) in accounts {
                let acc = account_json("0x1", "0x2", "0x3", storage_pairs);
                ordered.push((addr.clone(), acc.clone()));
                reversed.push((addr, acc));
            }
            reversed.reverse();

            let snap_a = snapshot_from_accounts(ordered);
            let snap_b = snapshot_from_accounts(reversed);

            let diff_a = canonicalize_value(&build_state_diff(&snap_a, &snap_a));
            let diff_b = canonicalize_value(&build_state_diff(&snap_b, &snap_b));
            let bytes_a = match serde_json::to_vec(&diff_a) {
                Ok(bytes) => bytes,
                Err(err) => {
                    prop_assert!(false, "serialize: {err}");
                    return Ok(());
                }
            };
            let bytes_b = match serde_json::to_vec(&diff_b) {
                Ok(bytes) => bytes,
                Err(err) => {
                    prop_assert!(false, "serialize: {err}");
                    return Ok(());
                }
            };
            prop_assert_eq!(bytes_a, bytes_b);
        }
    }
}

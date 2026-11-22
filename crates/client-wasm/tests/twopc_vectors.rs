//! The shared vectors of the two-party key schedule `split-public-2`
//! (`test/fixtures/twopc-hash-vectors.json`, a byte-identical copy of
//! `crypto/conformance/twopc-hash-vectors.json` in routstr-confidential),
//! recomputed by the vendored `twopc` as this build compiles it: natively
//! (`cargo test -p client-wasm`) and on wasm32 (wasm-bindgen-test-runner),
//! where AES and the GF(2^64) arithmetic run without the native AES and
//! carry-less multiply instructions. The vendored crate's own test
//! (`hash_vectors_match_conformance_file`) reads the same file through
//! `crates/vendor/conformance/`.

use mpz_core::Block;
use mpz_fields::p256::P256 as Fp;
use serde_json::Value;
use sha2::{Digest, Sha256};
use twopc::gc;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen_test::wasm_bindgen_test as test;

const FILE: &str = include_str!("../../../test/fixtures/twopc-hash-vectors.json");

fn vectors() -> Value {
    serde_json::from_str(FILE).expect("vector file")
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap_or_else(|| panic!("not a string: {v}"))
}
fn h64(v: &Value) -> u64 {
    u64::from_str_radix(s(v), 16).unwrap()
}
fn h128(v: &Value) -> u128 {
    u128::from_str_radix(s(v), 16).unwrap()
}
fn bytes<const N: usize>(v: &Value) -> [u8; N] {
    hex::decode(s(v)).unwrap().try_into().unwrap()
}
fn int(v: &Value) -> usize {
    v.as_u64().unwrap() as usize
}
fn bu(x: u128) -> Block {
    Block::new(x.to_le_bytes())
}
fn ub(b: Block) -> u128 {
    u128::from_le_bytes(b.to_bytes())
}
/// A field element from a big-endian hex integer, and back.
fn fp(v: &Value) -> Fp {
    let mut le: [u8; 32] = bytes(v);
    le.reverse();
    Fp::try_from(le).expect("below p")
}
fn fp_hex(x: Fp) -> String {
    let mut le: [u8; 32] = x.into();
    le.reverse();
    hex::encode(le)
}

#[test]
fn gf64_and_sigma() {
    let v = vectors();
    for c in v["xtime"].as_array().unwrap() {
        assert_eq!(gc::gf64::xtime(h64(&c["a"])), h64(&c["xtime"]), "{c}");
    }
    for c in v["gf64_mul"].as_array().unwrap() {
        assert_eq!(gc::gf64::mul(h64(&c["a"]), h64(&c["b"])), h64(&c["product"]), "{c}");
    }
    for c in v["sigma"].as_array().unwrap() {
        assert_eq!(gc::gf64::sigma(h128(&c["y"])), h128(&c["sigma"]), "{c}");
    }
}

#[test]
fn garbling_hash() {
    let v = vectors();
    let cases = v["h_g"].as_array().unwrap();
    assert!(!cases.is_empty());
    for c in cases {
        let hg = gc::HashG::new(&bytes(&c["hparams"]));
        let (x, tau) = (h128(&c["x"]), c["tau"].as_u64().unwrap());
        assert_eq!(tau, 3 * c["gid"].as_u64().unwrap() + c["slot"].as_u64().unwrap());
        let h = hg.h(x, tau);
        assert_eq!(h, h128(&c["h_g"]), "{c}");
        assert_eq!(hg.h_many([x, x ^ 1], [tau, tau]), [h, hg.h(x ^ 1, tau)]);
        assert_eq!(h as u64, h64(&c["half"]));
        assert_eq!((h >> 127) as u64, c["bit"].as_u64().unwrap());
    }
}

#[test]
fn row_params_and_check_rows() {
    let v = vectors();
    for c in v["row_params"].as_array().unwrap() {
        let seed: [u8; 32] = bytes(&c["seed"]);
        let hp: [u8; 32] = bytes(&c["hparams"]);
        let rp: [u8; 32] = Sha256::new()
            .chain_update(b"routstr-twopc-ag chi")
            .chain_update(seed)
            .chain_update(b"row-params")
            .chain_update(hp)
            .finalize()
            .into();
        assert_eq!(hex::encode(rp), s(&c["rparams"]), "{c}");
    }
    let rows = v["row"].as_array().unwrap();
    assert!(!rows.is_empty());
    for c in rows {
        let hg = gc::HashG::new(&bytes(&c["hparams"]));
        let rh = gc::RowHash::new(&hg, &bytes(&c["rparams"]));
        let (x, st, idx) = (bu(h128(&c["x"])), int(&c["stage"]), int(&c["idx"]));
        assert_eq!(rh.row(x, st, idx), h64(&c["row"]), "{c}");
        let want = (h128(&c["h_g"]), h128(&c["u_r"]), h128(&c["aes_in"]), h128(&c["aes_out"]));
        assert_eq!(rh.trace(x, st, idx), want, "{c}");
    }
}

#[test]
fn three_halves_gate() {
    let v = vectors();
    let g = &v["gate"];
    let hg = gc::HashG::new(&bytes(&g["hparams"]));
    let (a0, b0, delta) = (bu(h128(&g["a0"])), bu(h128(&g["b0"])), bu(h128(&g["delta"])));
    let gid = g["gid"].as_u64().unwrap();
    let dice = [g["dice"][0] == 1, g["dice"][1] == 1];
    let (k0, gate) = gc::and_garble3(&hg, a0, b0, delta, gid, dice);
    assert_eq!(ub(k0), h128(&g["k0"]));
    assert_eq!(gate.g.map(|x| format!("{x:016x}")).to_vec(), g["g"].as_array().unwrap().iter().map(|x| s(x).to_string()).collect::<Vec<_>>());
    assert_eq!(gate.z as u64, g["z"].as_u64().unwrap());
    for e in g["eval"].as_array().unwrap() {
        let out = gc::and_eval3(&hg, bu(h128(&e["label_a"])), bu(h128(&e["label_b"])), &gate, gid);
        assert_eq!(ub(out), h128(&e["out"]), "{e}");
    }
}

#[test]
fn input_label_commitments() {
    let v = vectors();
    for c in v["input_label_commitment"].as_array().unwrap() {
        let salt: [u8; 16] = bytes(&c["in_salt"]);
        let label: [u8; 16] = bytes(&c["label"]);
        let h = Sha256::new()
            .chain_update(b"routstr-twopc-ag input label")
            .chain_update(salt)
            .chain_update((int(&c["w"]) as u32).to_be_bytes())
            .chain_update([c["p"].as_u64().unwrap() as u8])
            .chain_update(label)
            .finalize();
        assert_eq!(hex::encode(&h[..16]), s(&c["com"]), "{c}");
    }
}

#[test]
fn masked_input() {
    let v = vectors();
    for c in v["masked_input"].as_array().unwrap() {
        let (x_n, rho, x_c) = (fp(&c["x_n"]), fp(&c["rho"]), fp(&c["x_c"]));
        let delta = x_n - rho;
        assert_eq!(fp_hex(delta), s(&c["delta"]), "{c}");
        let le: [u8; 32] = delta.into();
        assert_eq!(hex::encode(le), s(&c["delta_le"]));
        assert_eq!(fp_hex(x_c + delta), s(&c["x_c_prime"]));
        assert_eq!(fp_hex(x_c + delta + rho), s(&c["sum"]));
        assert_eq!(fp_hex(x_c + delta + rho), fp_hex(x_c + x_n));
    }
}

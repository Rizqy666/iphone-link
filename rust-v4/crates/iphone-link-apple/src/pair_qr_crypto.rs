//! Pure-Rust building blocks for QR/cableless remote pairing.
//!
//! This module deliberately keeps its dependencies to `std` plus the crate's existing
//! `win_cng` helpers. It contains:
//!
//! * a small unsigned big integer (`BigInt`), sufficient for the RFC 5054 3072-bit group;
//! * SRP-6a client/server implementations matching `pymobiledevice3.remote.srp`;
//! * HomeKit-style TLV8 framing;
//! * the OPACK subset needed to encode/decode Pair-Setup identities.
//!
//! The module has no side effects and does not depend on `lib.rs` re-exports.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::win_cng::{fill_random, sha512, sha512_chunks};

// ---------------------------------------------------------------------------
// Constants shared by the SRP implementation
// ---------------------------------------------------------------------------

const PAIR_SETUP_USERNAME: &str = "Pair-Setup";
/// `(N.bit_length() + 7) / 8` for the RFC 5054 3072-bit group.
const PUBLIC_LEN: usize = 384;
/// `secrets.randbits(1024)` in the Python implementation.
const PRIVATE_BYTES: usize = 128;

/// RFC 5054 appendix A, 3072-bit group (same value as pymobiledevice3/remote/srp.py).
const N_HEX: &str = concat!(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA6",
    "3B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245",
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F2411",
    "7C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F",
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08",
    "CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9",
    "DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D",
    "04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7",
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D8760273",
    "3EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB31",
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF",
);

fn hex_nibble(b: u8) -> u8 {
    match b {
        b'0'..=b'9' => b - b'0',
        b'a'..=b'f' => b - b'a' + 10,
        b'A'..=b'F' => b - b'A' + 10,
        _ => panic!("invalid hex digit in SRP modulus"),
    }
}

fn big_from_hex(hex: &str) -> BigInt {
    let raw = hex.as_bytes();
    let mut bytes = Vec::with_capacity((hex.len() + 1) / 2);
    let start = if hex.len() % 2 == 1 {
        bytes.push(hex_nibble(raw[0]));
        1
    } else {
        0
    };
    for pair in raw[start..].chunks(2) {
        bytes.push((hex_nibble(pair[0]) << 4) | hex_nibble(pair[1]));
    }
    BigInt::from_be_bytes(&bytes)
}

fn sr_n() -> BigInt {
    big_from_hex(N_HEX)
}

fn sr_g() -> BigInt {
    BigInt::from_u32(5)
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

// ---------------------------------------------------------------------------
// BigInt
// ---------------------------------------------------------------------------

/// Minimal unsigned big integer: little-endian `u32` limbs, always normalized
/// (at least one limb; the most significant limb is non-zero except for zero itself).
///
/// Multiplication is schoolbook `O(n*m)`; modular multiplication uses Montgomery
/// reduction for odd moduli, so 3072-bit exponentiation with 1024-bit exponents is
/// comfortably fast enough for a pairing handshake.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BigInt {
    limbs: Vec<u32>,
}

impl BigInt {
    /// Construct from a big-endian byte string (empty means zero).
    pub fn from_be_bytes(bytes: &[u8]) -> Self {
        let mut limbs = vec![0u32; ((bytes.len() + 3) / 4).max(1)];
        for (i, &byte) in bytes.iter().rev().enumerate() {
            limbs[i / 4] |= (byte as u32) << ((i % 4) * 8);
        }
        let mut value = Self { limbs };
        value.trim();
        value
    }

    fn from_u32(value: u32) -> Self {
        Self { limbs: vec![value] }
    }

    fn zero() -> Self {
        Self::from_u32(0)
    }

    fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }

    fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }

    fn trim(&mut self) {
        while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
            self.limbs.pop();
        }
    }

    /// Big-endian encoding with no leading zero bytes. Python's `_to_bytes`
    /// encodes zero as a single `0x00` byte; we match that here.
    pub fn to_be_bytes_minimal(&self) -> Vec<u8> {
        let mut full = Vec::with_capacity(self.limbs.len() * 4);
        for &limb in &self.limbs {
            full.extend_from_slice(&limb.to_le_bytes());
        }
        full.reverse();
        let first = full.iter().position(|&b| b != 0).unwrap_or(full.len() - 1);
        full[first..].to_vec()
    }

    /// Big-endian encoding exactly `len` bytes long (zero-padded on the left).
    ///
    /// Panics if the value does not fit; callers control the public sizes, so this
    /// mirrors Python's `int.to_bytes(len, 'big')` failure mode.
    pub fn to_be_bytes_padded(&self, len: usize) -> Vec<u8> {
        let minimal = self.to_be_bytes_minimal();
        assert!(
            minimal.len() <= len,
            "BigInt does not fit in {len} bytes (needs {})",
            minimal.len()
        );
        let mut out = vec![0u8; len];
        out[len - minimal.len()..].copy_from_slice(&minimal);
        out
    }

    /// Inherent comparison; `Ord` is implemented in terms of this as well.
    pub fn cmp(&self, other: &Self) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => continue,
                        order => return order,
                    }
                }
                Ordering::Equal
            }
            order => order,
        }
    }

    /// Unsigned addition.
    pub fn add(&self, other: &Self) -> Self {
        let n = self.limbs.len().max(other.limbs.len());
        let mut out = Vec::with_capacity(n + 1);
        let mut carry = 0u64;
        for i in 0..n {
            let a = self.limbs.get(i).copied().unwrap_or(0) as u64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as u64;
            let sum = a + b + carry;
            out.push(sum as u32);
            carry = sum >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        let mut result = Self { limbs: out };
        result.trim();
        result
    }

    /// Unsigned subtraction; panics if `self < other`.
    pub fn sub(&self, other: &Self) -> Self {
        assert!(self.cmp(other) != Ordering::Less, "BigInt::sub underflow");
        let mut out = Vec::with_capacity(self.limbs.len());
        let mut borrow = 0i64;
        for i in 0..self.limbs.len() {
            let a = self.limbs[i] as i64;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i64;
            let mut diff = a - b - borrow;
            if diff < 0 {
                diff += 1i64 << 32;
                borrow = 1;
            } else {
                borrow = 0;
            }
            out.push(diff as u32);
        }
        debug_assert_eq!(borrow, 0);
        let mut result = Self { limbs: out };
        result.trim();
        result
    }

    /// Schoolbook multiplication using `u128` accumulators (no intermediate overflow).
    pub fn mul(&self, other: &Self) -> Self {
        if self.is_zero() || other.is_zero() {
            return Self::zero();
        }
        let n = self.limbs.len();
        let m = other.limbs.len();
        let mut out = vec![0u32; n + m];
        for i in 0..n {
            let a = self.limbs[i] as u128;
            let mut carry = 0u128;
            for j in 0..m {
                let acc = out[i + j] as u128 + a * (other.limbs[j] as u128) + carry;
                out[i + j] = acc as u32;
                carry = acc >> 32;
            }
            let mut k = i + m;
            while carry != 0 {
                let acc = out[k] as u128 + carry;
                out[k] = acc as u32;
                carry = acc >> 32;
                k += 1;
            }
        }
        let mut result = Self { limbs: out };
        result.trim();
        result
    }

    /// Multiply by a single limb (used by modular reduction).
    fn mul_small(&self, factor: u32) -> Self {
        if factor == 0 || self.is_zero() {
            return Self::zero();
        }
        let mut out = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u64;
        for &limb in &self.limbs {
            let acc = (limb as u64) * (factor as u64) + carry;
            out.push(acc as u32);
            carry = acc >> 32;
        }
        if carry != 0 {
            out.push(carry as u32);
        }
        let mut result = Self { limbs: out };
        result.trim();
        result
    }

    fn shr1(&mut self) {
        let mut carry = 0u32;
        for limb in self.limbs.iter_mut().rev() {
            let next = *limb & 1;
            *limb = (*limb >> 1) | (carry << 31);
            carry = next;
        }
        self.trim();
    }

    /// Reduce an arbitrary value modulo `modulus` (which must be non-zero).
    ///
    /// Processes one 32-bit limb at a time. Keeping the remainder below the modulus
    /// after each step means the quotient limb is at most `u32::MAX`; a binary search
    /// finds it without relying on a normalized top limb.
    fn mod_reduce(&self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        if self.cmp(modulus) == Ordering::Less {
            return self.clone();
        }
        let mut remainder = Self::zero();
        for &limb in self.limbs.iter().rev() {
            remainder.limbs.insert(0, limb);
            remainder.trim();
            let mut lo = 0u64;
            let mut hi = u32::MAX as u64;
            while lo < hi {
                let mid = lo + (hi - lo + 1) / 2;
                if modulus.mul_small(mid as u32).cmp(&remainder) != Ordering::Greater {
                    lo = mid;
                } else {
                    hi = mid - 1;
                }
            }
            if lo != 0 {
                remainder = remainder.sub(&modulus.mul_small(lo as u32));
            }
        }
        debug_assert!(remainder.cmp(modulus) == Ordering::Less);
        remainder
    }

    /// `(self * other) mod modulus`.
    pub fn mod_mul(&self, other: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let a = self.mod_reduce(modulus);
        let b = other.mod_reduce(modulus);
        match Montgomery::new(modulus) {
            Some(ctx) => {
                let a_mont = ctx.to_mont(&a);
                let b_mont = ctx.to_mont(&b);
                ctx.from_mont(&ctx.mul_mont(&a_mont, &b_mont))
            }
            None => a.mul(&b).mod_reduce(modulus),
        }
    }

    /// `(self - other) mod modulus` for arbitrary (possibly unordered) operands.
    pub fn mod_sub(&self, other: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let a = self.mod_reduce(modulus);
        let b = other.mod_reduce(modulus);
        match a.cmp(&b) {
            Ordering::Less => {
                let diff = b.sub(&a);
                let mut result = modulus.sub(&diff);
                while result.cmp(modulus) != Ordering::Less {
                    result = result.sub(modulus);
                }
                result
            }
            _ => a.sub(&b),
        }
    }

    /// Right-to-left binary exponentiation, `self^exponent mod modulus`.
    ///
    /// Reuses one Montgomery context for the whole exponentiation; recomputing
    /// `R^2 mod N` per multiplication would add an unnecessary `O(bits * limbs^2)`
    /// term per exponent bit.
    pub fn mod_pow(&self, exponent: &Self, modulus: &Self) -> Self {
        assert!(!modulus.is_zero(), "modulus must be non-zero");
        let ctx = Montgomery::new(modulus);
        let mul = |a: &Self, b: &Self| -> Self {
            match &ctx {
                Some(context) => context.mul_mont(a, b),
                None => a.mul(b).mod_reduce(modulus),
            }
        };
        let mut base = self.mod_reduce(modulus);
        let mut result = Self::from_u32(1).mod_reduce(modulus);
        // Keep both accumulator and base in the Montgomery domain for the whole
        // exponentiation; only convert the final result back.
        if let Some(context) = &ctx {
            base = context.to_mont(&base);
            result = context.to_mont(&result);
        }
        let mut exp = exponent.clone();
        while !exp.is_zero() {
            if exp.limbs[0] & 1 == 1 {
                result = mul(&result, &base);
            }
            exp.shr1();
            if !exp.is_zero() {
                base = mul(&base, &base);
            }
        }
        match &ctx {
            Some(context) => context.from_mont(&result),
            None => result,
        }
    }
}

impl Ord for BigInt {
    fn cmp(&self, other: &Self) -> Ordering {
        BigInt::cmp(self, other)
    }
}

impl PartialOrd for BigInt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(BigInt::cmp(self, other))
    }
}

/// Montgomery context for odd moduli: `R = 2^(32 * limbs)`, `R^2 mod N`, and
/// `-N^-1 mod 2^32`. Created once per exponentiation (and per standalone
/// `mod_mul`) so the `R^2` precomputation is not repeated for every bit.
struct Montgomery {
    modulus: BigInt,
    n_prime: u32,
    r2: BigInt,
}

impl Montgomery {
    fn new(modulus: &BigInt) -> Option<Self> {
        if modulus.is_zero() || !modulus.is_odd() {
            return None;
        }
        // Newton iteration doubles the number of correct low bits each pass:
        // 1 -> 2 -> 4 -> 8 -> 16 -> 32.
        let mut inv = 1u32;
        for _ in 0..5 {
            inv = inv.wrapping_mul(2u32.wrapping_sub(modulus.limbs[0].wrapping_mul(inv)));
        }
        let n_prime = inv.wrapping_neg();

        let mut r2 = BigInt::from_u32(1);
        for _ in 0..(64 * modulus.limbs.len()) {
            r2 = r2.add(&r2);
            if r2.cmp(modulus) != Ordering::Less {
                r2 = r2.sub(modulus);
            }
        }
        Some(Self {
            modulus: modulus.clone(),
            n_prime,
            r2,
        })
    }

    /// `t * R^-1 mod N`, for `t < N * R`.
    fn reduce(&self, t: &BigInt) -> BigInt {
        let k = self.modulus.limbs.len();
        let mut limbs = vec![0u32; 2 * k + 1];
        for (i, &limb) in t.limbs.iter().enumerate() {
            limbs[i] = limb;
        }
        for i in 0..k {
            let m = (limbs[i] as u64 * self.n_prime as u64) as u32;
            if m == 0 {
                continue;
            }
            let mut carry = 0u128;
            for j in 0..k {
                let idx = i + j;
                let acc =
                    limbs[idx] as u128 + (m as u128) * (self.modulus.limbs[j] as u128) + carry;
                limbs[idx] = acc as u32;
                carry = acc >> 32;
            }
            let mut idx = i + k;
            while carry != 0 {
                let acc = limbs[idx] as u128 + carry;
                limbs[idx] = acc as u32;
                carry = acc >> 32;
                idx += 1;
            }
        }
        let mut result = BigInt {
            limbs: limbs[k..].to_vec(),
        };
        result.trim();
        while result.cmp(&self.modulus) != Ordering::Less {
            result = result.sub(&self.modulus);
        }
        result
    }

    /// Convert a reduced value into the Montgomery domain: `a * R mod N`.
    fn to_mont(&self, a: &BigInt) -> BigInt {
        self.reduce(&a.mul(&self.r2))
    }

    /// Convert a Montgomery-domain value back: `a * R^-1 mod N`.
    fn from_mont(&self, a: &BigInt) -> BigInt {
        self.reduce(a)
    }

    /// Multiply two Montgomery-domain values, returning `a * b * R^-1 mod N`
    /// (still in the Montgomery domain).
    fn mul_mont(&self, a: &BigInt, b: &BigInt) -> BigInt {
        self.reduce(&a.mul(b))
    }
}

// ---------------------------------------------------------------------------
// SRP-6a (Pair-Setup, SHA-512, RFC 5054 3072-bit group)
// ---------------------------------------------------------------------------

fn hash_int(parts: &[&[u8]]) -> BigInt {
    BigInt::from_be_bytes(&sha512_chunks(parts))
}

/// `k = H(PAD(N) | PAD(g))`, with the prime hashed as minimal bytes and the
/// generator padded to 384 bytes (as in `pymobiledevice3`).
fn multiplier() -> BigInt {
    let n = sr_n();
    let n_min = n.to_be_bytes_minimal();
    let g_pad = sr_g().to_be_bytes_padded(PUBLIC_LEN);
    hash_int(&[&n_min, &g_pad])
}

/// `x = H(salt | H("Pair-Setup:pin"))`.
fn password_hash(pin: &str, salt: &[u8]) -> BigInt {
    let inner = sha512(format!("{PAIR_SETUP_USERNAME}:{pin}").as_bytes());
    hash_int(&[salt, &inner])
}

fn xor_bytes(a: &[u8; 64], b: &[u8; 64]) -> Vec<u8> {
    (0..64).map(|i| a[i] ^ b[i]).collect()
}

/// `u = H(PAD(A) | PAD(B))`.
fn scrambler(client_public: &BigInt, server_public: &BigInt) -> BigInt {
    let a_pad = client_public.to_be_bytes_padded(PUBLIC_LEN);
    let b_pad = server_public.to_be_bytes_padded(PUBLIC_LEN);
    hash_int(&[&a_pad, &b_pad])
}

/// `M1 = H(H(N) XOR H(g) | H(I) | salt | A | B | K)` and
/// `M2 = H(A | M1 | K)`, with integer fields encoded minimally.
fn session_proofs(a_min: &[u8], b_min: &[u8], salt: &[u8], key: &[u8; 64]) -> ([u8; 64], [u8; 64]) {
    let hn = sha512(&sr_n().to_be_bytes_minimal());
    let hg = sha512(&[5u8]);
    let group_hash = BigInt::from_be_bytes(&xor_bytes(&hn, &hg)).to_be_bytes_minimal();
    let username_hash =
        BigInt::from_be_bytes(&sha512(PAIR_SETUP_USERNAME.as_bytes())).to_be_bytes_minimal();
    let m1 = sha512_chunks(&[&group_hash, &username_hash, salt, a_min, b_min, key]);
    let m2 = sha512_chunks(&[a_min, &m1, key]);
    (m1, m2)
}

/// SRP-6a server side of Pair-Setup (the device displaying the PIN).
pub struct SrpServer {
    salt: [u8; 16],
    verifier: BigInt,
    private: BigInt,
    public: BigInt,
    key: Option<[u8; 64]>,
    expected_client_proof: Option<[u8; 64]>,
    server_proof: Option<[u8; 64]>,
}

impl SrpServer {
    /// Create a server for `pin` and `salt`. The private value `b` is 1024 random
    /// bits and is regenerated until `B` encodes to exactly 384 bytes, matching
    /// the wire shape expected by the device.
    pub fn new(pin: &str, salt: &[u8; 16]) -> Result<Self, String> {
        let n = sr_n();
        let g = sr_g();
        let k = multiplier();
        let x = password_hash(pin, salt);
        let verifier = g.mod_pow(&x, &n);

        let mut random = [0u8; PRIVATE_BYTES];
        loop {
            fill_random(&mut random)?;
            let private = BigInt::from_be_bytes(&random);
            let g_b = g.mod_pow(&private, &n);
            let mut public = k.mod_mul(&verifier, &n).add(&g_b);
            if public.cmp(&n) != Ordering::Less {
                public = public.sub(&n);
            }
            if public.to_be_bytes_minimal().len() == PUBLIC_LEN {
                return Ok(Self {
                    salt: *salt,
                    verifier,
                    private,
                    public,
                    key: None,
                    expected_client_proof: None,
                    server_proof: None,
                });
            }
        }
    }

    /// `B`, minimally encoded big-endian.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.to_be_bytes_minimal()
    }

    /// `B`, zero-padded to the group length (384 bytes).
    pub fn public_padded(&self) -> Vec<u8> {
        self.public.to_be_bytes_padded(PUBLIC_LEN)
    }

    /// Derive the shared key and both proofs from the client's public value `A`.
    pub fn process(&mut self, client_public: &[u8]) -> Result<(), String> {
        if client_public.len() > PUBLIC_LEN {
            return Err("client public value is longer than the SRP group".to_string());
        }
        let n = sr_n();
        let a = BigInt::from_be_bytes(client_public);
        if a.mod_reduce(&n).is_zero() {
            return Err("invalid SRP client public value".to_string());
        }

        let u = scrambler(&a, &self.public);
        let v_u = self.verifier.mod_pow(&u, &n);
        let premaster = a.mod_mul(&v_u, &n).mod_pow(&self.private, &n);
        let key = sha512(&premaster.to_be_bytes_minimal());

        let a_min = a.to_be_bytes_minimal();
        let b_min = self.public.to_be_bytes_minimal();
        let (m1, m2) = session_proofs(&a_min, &b_min, &self.salt, &key);
        self.key = Some(key);
        self.expected_client_proof = Some(m1);
        self.server_proof = Some(m2);
        Ok(())
    }

    /// SHA-512 of the premaster secret; all zeroes before `process`.
    pub fn session_key(&self) -> [u8; 64] {
        self.key.unwrap_or([0u8; 64])
    }

    /// `M2`, all zeroes before `process`.
    pub fn server_proof(&self) -> [u8; 64] {
        self.server_proof.unwrap_or([0u8; 64])
    }

    /// Constant-time verification of the client's `M1`.
    pub fn verify_client_proof(&self, proof: &[u8]) -> bool {
        match &self.expected_client_proof {
            Some(expected) => constant_time_eq(proof, expected),
            None => false,
        }
    }
}

/// SRP-6a client side, mirroring `pymobiledevice3.remote.srp.SrpClient`.
/// Primarily useful for local round-trip tests and hosts implementing the device role.
pub struct SrpClient {
    pin: String,
    private: BigInt,
    public: BigInt,
    key: Option<[u8; 64]>,
    proof: Option<[u8; 64]>,
    expected_server_proof: Option<[u8; 64]>,
}

impl SrpClient {
    /// Create a client. When `private` is `None`, 1024 random bits are used.
    pub fn new(pin: &str, private: Option<BigInt>) -> Result<Self, String> {
        let private = match private {
            Some(value) => value,
            None => {
                let mut random = [0u8; PRIVATE_BYTES];
                fill_random(&mut random)?;
                BigInt::from_be_bytes(&random)
            }
        };
        let public = sr_g().mod_pow(&private, &sr_n());
        Ok(Self {
            pin: pin.to_string(),
            private,
            public,
            key: None,
            proof: None,
            expected_server_proof: None,
        })
    }

    /// `A`, minimally encoded big-endian.
    pub fn public_bytes(&self) -> Vec<u8> {
        self.public.to_be_bytes_minimal()
    }

    /// Derive the shared key and proofs from the server's `B` and the salt.
    pub fn process(&mut self, server_public: &[u8], salt: &[u8]) -> Result<(), String> {
        if server_public.len() > PUBLIC_LEN {
            return Err("server public value is longer than the SRP group".to_string());
        }
        let n = sr_n();
        let g = sr_g();
        let server_public = BigInt::from_be_bytes(server_public);
        if server_public.mod_reduce(&n).is_zero() {
            return Err("invalid SRP server public value".to_string());
        }

        let u = scrambler(&self.public, &server_public);
        let x = password_hash(&self.pin, salt);
        let g_x = g.mod_pow(&x, &n);
        let base = server_public.mod_sub(&multiplier().mod_mul(&g_x, &n), &n);
        let exponent = self.private.add(&u.mul(&x));
        let premaster = base.mod_pow(&exponent, &n);
        let key = sha512(&premaster.to_be_bytes_minimal());

        let a_min = self.public.to_be_bytes_minimal();
        let b_min = server_public.to_be_bytes_minimal();
        let (m1, m2) = session_proofs(&a_min, &b_min, salt, &key);
        self.key = Some(key);
        self.proof = Some(m1);
        self.expected_server_proof = Some(m2);
        Ok(())
    }

    /// Client proof `M1`, all zeroes before `process`.
    pub fn proof(&self) -> [u8; 64] {
        self.proof.unwrap_or([0u8; 64])
    }

    /// SHA-512 of the premaster secret; all zeroes before `process`.
    pub fn session_key(&self) -> [u8; 64] {
        self.key.unwrap_or([0u8; 64])
    }

    /// Constant-time verification of the server's `M2`.
    pub fn verify_server_proof(&self, proof: &[u8]) -> bool {
        match &self.expected_server_proof {
            Some(expected) => constant_time_eq(proof, expected),
            None => false,
        }
    }
}

// ---------------------------------------------------------------------------
// TLV8 (Pair-Setup components)
// ---------------------------------------------------------------------------

/// Encode TLV8 items, splitting values longer than 255 bytes into repeated-type
/// fragments (and emitting a zero-length item for an empty value).
pub fn tlv_build(items: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (kind, value) in items {
        if value.is_empty() {
            out.push(*kind);
            out.push(0);
            continue;
        }
        for chunk in value.chunks(255) {
            out.push(*kind);
            out.push(chunk.len() as u8);
            out.extend_from_slice(chunk);
        }
    }
    out
}

/// Parse TLV8 items, concatenating fragments of the same type. An incomplete
/// trailing item is ignored, matching `PairingDataComponentTLVBuf.parse`.
pub fn tlv_parse(data: &[u8]) -> BTreeMap<u8, Vec<u8>> {
    let mut result: BTreeMap<u8, Vec<u8>> = BTreeMap::new();
    let mut offset = 0usize;
    while offset + 2 <= data.len() {
        let kind = data[offset];
        let len = data[offset + 1] as usize;
        let start = offset + 2;
        if start + len > data.len() {
            break;
        }
        result
            .entry(kind)
            .or_default()
            .extend_from_slice(&data[start..start + len]);
        offset = start + len;
    }
    result
}

// ---------------------------------------------------------------------------
// OPACK (opack2 0.2.0 subset used by Pair-Setup)
// ---------------------------------------------------------------------------

/// The identity fields we care about from an OPACK peer/host dictionary.
///
/// Presence flags are private on purpose: `Default` values must never be mistaken
/// for identity data received from a device. `opack_parse_identity` validates them.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PeerIdentity {
    pub account_id: String,
    pub alt_irk: [u8; 16],
    pub model: String,
    pub name: String,
    pub udid: String,
    seen_account_id: bool,
    seen_alt_irk: bool,
    seen_model: bool,
    seen_name: bool,
}

impl PeerIdentity {
    /// Require the fields `PeerDeviceInfo.from_info_dict` enforces on the Python side.
    pub fn validate(&self) -> Result<(), String> {
        if !self.seen_alt_irk {
            return Err("device pairing info has a missing or invalid altIRK".to_string());
        }
        for (seen, field) in [
            (self.seen_account_id, "accountID"),
            (self.seen_model, "model"),
            (self.seen_name, "name"),
        ] {
            if !seen {
                return Err(format!("device pairing info is missing {field}"));
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
enum OpackValue {
    Str(String),
    Bytes(Vec<u8>),
    /// Booleans, integers, containers, floats, timestamps and back-references:
    /// decoded so the stream advances correctly and reference slots stay aligned,
    /// but not used for the named identity fields.
    Other,
}

struct OpackParser<'a> {
    data: &'a [u8],
    pos: usize,
    /// Every referenceable decoded object, in decode order.
    objects: Vec<OpackValue>,
}

impl<'a> OpackParser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            objects: Vec::new(),
        }
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], String> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| "OPACK length overflow".to_string())?;
        if end > self.data.len() {
            return Err(format!(
                "truncated OPACK value at offset {}: need {len} bytes",
                self.pos
            ));
        }
        let slice = &self.data[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_be(&mut self, len: usize) -> Result<usize, String> {
        let bytes = self.take(len)?;
        let mut value = 0usize;
        for &b in bytes {
            value = value
                .checked_mul(256)
                .and_then(|v| v.checked_add(b as usize))
                .ok_or_else(|| "OPACK length too large on this platform".to_string())?;
        }
        Ok(value)
    }

    fn take_le_u64(&mut self, len: usize) -> Result<u64, String> {
        let bytes = self.take(len)?;
        let mut value = 0u64;
        for (i, &b) in bytes.iter().enumerate() {
            value |= (b as u64) << (8 * i);
        }
        Ok(value)
    }

    /// Read one object, returning its type byte (needed for terminator detection).
    fn read_value(&mut self, identity: &mut PeerIdentity) -> Result<(u8, OpackValue), String> {
        let kind = *self
            .take(1)?
            .first()
            .ok_or_else(|| "missing OPACK type byte".to_string())?;

        match kind {
            1 | 2 => Ok((kind, OpackValue::Other)), // bool: never referenceable
            3 => Ok((kind, OpackValue::Other)),     // terminator
            6 => {
                // Timestamp: 8-byte little-endian double, always referenceable.
                let _ = self.take_le_u64(8)?;
                self.objects.push(OpackValue::Other);
                Ok((kind, OpackValue::Other))
            }
            0x08..=0x36 => self.read_int(kind),
            0x40..=0x64 => {
                let size = match kind {
                    0x40..=0x60 => (kind - 0x40) as usize,
                    0x61 => self.take_be(1)?,
                    0x62 => self.take_be(2)?,
                    0x63 => self.take_be(4)?,
                    0x64 => self.take_be(8)?,
                    _ => unreachable!(),
                };
                let bytes = self.take(size)?;
                let text = std::str::from_utf8(bytes)
                    .map_err(|e| format!("invalid UTF-8 in OPACK string: {e}"))?
                    .to_string();
                let value = if text.is_empty() {
                    OpackValue::Str(text)
                } else {
                    let ref_value = OpackValue::Str(text.clone());
                    self.objects.push(ref_value);
                    OpackValue::Str(text)
                };
                Ok((kind, value))
            }
            0x70..=0x94 => {
                let size = match kind {
                    0x70..=0x90 => (kind - 0x70) as usize,
                    0x91 => self.take_be(1)?,
                    0x92 => self.take_be(2)?,
                    0x93 => self.take_be(4)?,
                    0x94 => self.take_be(8)?,
                    _ => unreachable!(),
                };
                let bytes = self.take(size)?.to_vec();
                let value = if bytes.len() > 1 {
                    self.objects.push(OpackValue::Bytes(bytes.clone()));
                    OpackValue::Bytes(bytes)
                } else {
                    OpackValue::Bytes(bytes)
                };
                Ok((kind, value))
            }
            0xA0..=0xC4 => {
                let index = if kind <= 0xC0 {
                    (kind - 0xA0) as usize
                } else {
                    // 1..=4 little-endian bytes.
                    self.take_le_u64((kind - 0xC0) as usize)? as usize
                };
                let value = self
                    .objects
                    .get(index)
                    .cloned()
                    .ok_or_else(|| format!("OPACK back-reference {index} out of range"))?;
                // Back-references themselves are not referenceable.
                Ok((kind, value))
            }
            0xD0..=0xDF => {
                if kind == 0xDF {
                    loop {
                        let (element_kind, _) = self.read_value(identity)?;
                        if element_kind == 3 {
                            break;
                        }
                    }
                } else {
                    for _ in 0..(kind - 0xD0) {
                        let _ = self.read_value(identity)?;
                    }
                }
                // Containers are never referenceable.
                Ok((kind, OpackValue::Other))
            }
            0xE0..=0xEF => {
                if kind == 0xEF {
                    loop {
                        let (key_kind, key) = self.read_value(identity)?;
                        let (_, value) = self.read_value(identity)?;
                        if key_kind == 3 {
                            break; // terminator key's value is discarded
                        }
                        assign_identity_field(identity, &key, &value);
                    }
                } else {
                    for _ in 0..(kind - 0xE0) {
                        let (_, key) = self.read_value(identity)?;
                        let (_, value) = self.read_value(identity)?;
                        assign_identity_field(identity, &key, &value);
                    }
                }
                // Dictionaries are never referenceable.
                Ok((kind, OpackValue::Other))
            }
            _ => Err(format!("unsupported OPACK object type 0x{kind:02X}")),
        }
    }

    fn read_int(&mut self, kind: u8) -> Result<(u8, OpackValue), String> {
        const INLINE_MAX: i128 = 0x27;
        let (value, float) = match kind {
            0x08..=0x2F => ((kind as i128) - 8, false),
            0x30 => (self.take(1)?[0] as i128, false),
            0x31 => {
                let bytes = self.take(2)?;
                let raw = u16::from_le_bytes([bytes[0], bytes[1]]);
                ((raw as i16) as i128, false)
            }
            0x32 => (self.take_le_u64(4)? as i128, false),
            0x33 => (self.take_le_u64(8)? as i128, false),
            0x35 => {
                let _ = self.take_le_u64(4)?;
                (0, true)
            }
            0x36 => {
                let _ = self.take_le_u64(8)?;
                (0, true)
            }
            _ => return Err(format!("invalid OPACK integer type 0x{kind:02X}")),
        };
        // `_is_referenceable`: floats always; ints only outside [-1, 0x27].
        // Back-references to them never feed an identity field, so a placeholder
        // is enough to keep the reference table indices correct.
        if float {
            self.objects.push(OpackValue::Other);
            Ok((kind, OpackValue::Other))
        } else {
            if value < -1 || value > INLINE_MAX {
                self.objects.push(OpackValue::Other);
            }
            Ok((kind, OpackValue::Other))
        }
    }
}

fn assign_identity_field(identity: &mut PeerIdentity, key: &OpackValue, value: &OpackValue) {
    let key = match key {
        OpackValue::Str(key) => key.as_str(),
        _ => return,
    };
    match key {
        "accountID" => {
            if let OpackValue::Str(s) = value {
                identity.account_id = s.clone();
                identity.seen_account_id = true;
            }
        }
        "altIRK" => {
            if let OpackValue::Bytes(bytes) = value {
                if bytes.len() == 16 {
                    identity.alt_irk.copy_from_slice(bytes);
                    identity.seen_alt_irk = true;
                }
            }
        }
        "model" => {
            if let OpackValue::Str(s) = value {
                identity.model = s.clone();
                identity.seen_model = true;
            }
        }
        "name" => {
            if let OpackValue::Str(s) = value {
                identity.name = s.clone();
                identity.seen_name = true;
            }
        }
        // The device's OPACK calls this `remotepairing_udid`; accept the bare
        // `udid` spelling too for locally produced payloads.
        "remotepairing_udid" | "udid" => {
            if let OpackValue::Str(s) = value {
                identity.udid = s.clone();
            }
        }
        _ => {}
    }
}

/// Parse the OPACK subset emitted by opack2 0.2.0 and extract identity fields.
/// Other keys, nested containers and unsupported scalar kinds are still decoded
/// so that back-reference indices stay aligned with opack2's table.
pub fn opack_parse_identity(data: &[u8]) -> Result<PeerIdentity, String> {
    let mut parser = OpackParser::new(data);
    let mut identity = PeerIdentity::default();
    let (kind, _) = parser.read_value(&mut identity)?;
    if !(0xE0..=0xEF).contains(&kind) {
        return Err("OPACK identity payload is not a dictionary".to_string());
    }
    identity.validate()?;
    Ok(identity)
}

fn opack_string(value: &str) -> Vec<u8> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len() + 9);
    if bytes.len() <= 0x20 {
        out.push(0x40 + bytes.len() as u8);
    } else if bytes.len() <= 0xFF {
        out.push(0x61);
        out.push(bytes.len() as u8);
    } else {
        panic!("OPACK host identity strings longer than 255 bytes are not supported");
    }
    out.extend_from_slice(bytes);
    out
}

fn opack_bytes(value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 9);
    if value.len() <= 0x20 {
        out.push(0x70 + value.len() as u8);
    } else if value.len() <= 0xFF {
        out.push(0x91);
        out.push(value.len() as u8);
    } else {
        panic!("OPACK host identity byte strings longer than 255 bytes are not supported");
    }
    out.extend_from_slice(value);
    out
}

/// Build the 8-entry short-form host identity dictionary used for Pair-Setup M5.
/// The fixed `btAddr`, `mac` and serial values match pymobiledevice3's host payload;
/// no back-references are emitted.
pub fn opack_build_host_identity(
    identifier: &str,
    host_alt_irk: &[u8; 16],
    model: &str,
    name: &str,
    udid: &str,
) -> Vec<u8> {
    let mut out = Vec::new();
    out.push(0xE8); // short-form dictionary with 8 entries
    out.extend_from_slice(&opack_string("accountID"));
    out.extend_from_slice(&opack_string(identifier));
    out.extend_from_slice(&opack_string("altIRK"));
    out.extend_from_slice(&opack_bytes(host_alt_irk));
    out.extend_from_slice(&opack_string("btAddr"));
    out.extend_from_slice(&opack_string("11:22:33:44:55:66"));
    out.extend_from_slice(&opack_string("mac"));
    out.extend_from_slice(&opack_bytes(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
    out.extend_from_slice(&opack_string("remotepairing_serial_number"));
    out.extend_from_slice(&opack_string("AAAAAAAAAAAA"));
    out.extend_from_slice(&opack_string("remotepairing_udid"));
    out.extend_from_slice(&opack_string(udid));
    out.extend_from_slice(&opack_string("model"));
    out.extend_from_slice(&opack_string(model));
    out.extend_from_slice(&opack_string("name"));
    out.extend_from_slice(&opack_string(name));
    out
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bigint_basics() {
        let a = BigInt::from_be_bytes(&[0xFF]);
        let b = BigInt::from_be_bytes(&[0x02]);
        assert_eq!(a.add(&b).to_be_bytes_minimal(), vec![0x01, 0x01]);
        assert_eq!(a.sub(&b).to_be_bytes_minimal(), vec![0xFD]);
        assert_eq!(a.mul(&b).to_be_bytes_minimal(), vec![0x01, 0xFE]);
        assert_eq!(BigInt::from_be_bytes(&[]).to_be_bytes_minimal(), vec![0x00]);
        assert_eq!(
            BigInt::from_be_bytes(&[0x01, 0x00]).to_be_bytes_padded(4),
            vec![0x00, 0x00, 0x01, 0x00]
        );

        let modulus = BigInt::from_be_bytes(&[0x1D]); // 29
        let three = BigInt::from_be_bytes(&[3]);
        assert_eq!(
            three.mod_pow(&three, &modulus).to_be_bytes_minimal(),
            vec![27]
        );
        assert_eq!(
            BigInt::from_be_bytes(&[2])
                .mod_sub(&BigInt::from_be_bytes(&[5]), &BigInt::from_be_bytes(&[7]))
                .to_be_bytes_minimal(),
            vec![4]
        );
    }

    #[test]
    fn srp_full_exchange() {
        let salt = [0x11u8; 16];
        let pin = "123456";
        let mut server = SrpServer::new(pin, &salt).expect("server setup");
        let client_private = BigInt::from_be_bytes(&[0x42u8; PRIVATE_BYTES]);
        let mut client = SrpClient::new(pin, Some(client_private)).expect("client setup");

        assert_eq!(server.public_bytes().len(), PUBLIC_LEN);
        client
            .process(&server.public_bytes(), &salt)
            .expect("client process");
        server
            .process(&client.public_bytes())
            .expect("server process");

        assert_eq!(server.session_key(), client.session_key());
        assert!(server.verify_client_proof(&client.proof()));
        assert!(client.verify_server_proof(&server.server_proof()));
        assert!(!server.verify_client_proof(&[0u8; 64]));
        assert!(!client.verify_server_proof(&[0u8; 64]));
    }

    #[test]
    fn tlv_fragments() {
        let long = vec![0x5Au8; 600];
        let encoded = tlv_build(&[(0x01, vec![1]), (0x02, long.clone())]);
        let parsed = tlv_parse(&encoded);
        assert_eq!(parsed.get(&0x01), Some(&vec![1]));
        assert_eq!(parsed.get(&0x02), Some(&long));

        // Incomplete trailing item is ignored.
        let mut truncated = encoded.clone();
        truncated.extend_from_slice(&[0x03, 0x04, 0xAA]);
        assert_eq!(tlv_parse(&truncated), parsed);
    }

    #[test]
    fn opack_identity_round_trip() {
        let identifier = "host-identifier-1234";
        let alt_irk = [
            0xE9, 0xE8, 0x2D, 0xC0, 0x6A, 0x49, 0x79, 0x6B, 0x56, 0x6F, 0x54, 0x00, 0x19, 0xB1,
            0xC7, 0x7B,
        ];
        let model = "computer-model";
        let name = "test host";
        let udid = "00000000-1111-2222-3333-444444444444";
        let encoded = opack_build_host_identity(identifier, &alt_irk, model, name, udid);
        assert_eq!(encoded[0], 0xE8);

        let parsed = opack_parse_identity(&encoded).expect("parse identity");
        assert_eq!(parsed.account_id, identifier);
        assert_eq!(parsed.alt_irk, alt_irk);
        assert_eq!(parsed.model, model);
        assert_eq!(parsed.name, name);
        assert_eq!(parsed.udid, udid);
    }

    #[test]
    fn opack_identity_rejects_missing_or_wrong_fields() {
        let mut missing_alt_irk = vec![0xE3];
        missing_alt_irk.extend_from_slice(&opack_string("accountID"));
        missing_alt_irk.extend_from_slice(&opack_string("account"));
        missing_alt_irk.extend_from_slice(&opack_string("model"));
        missing_alt_irk.extend_from_slice(&opack_string("iPhone17,3"));
        missing_alt_irk.extend_from_slice(&opack_string("name"));
        missing_alt_irk.extend_from_slice(&opack_string("iPhone"));
        assert!(opack_parse_identity(&missing_alt_irk).is_err());

        let mut short_alt_irk = vec![0xE4];
        short_alt_irk.extend_from_slice(&opack_string("accountID"));
        short_alt_irk.extend_from_slice(&opack_string("account"));
        short_alt_irk.extend_from_slice(&opack_string("altIRK"));
        short_alt_irk.extend_from_slice(&opack_bytes(&[0x11; 15]));
        short_alt_irk.extend_from_slice(&opack_string("model"));
        short_alt_irk.extend_from_slice(&opack_string("iPhone17,3"));
        short_alt_irk.extend_from_slice(&opack_string("name"));
        short_alt_irk.extend_from_slice(&opack_string("iPhone"));
        assert!(opack_parse_identity(&short_alt_irk).is_err());
    }
}

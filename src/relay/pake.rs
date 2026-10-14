//! Legacy croc relay admission only (schollz/pake v3.2.0, SIEC255).
//! Fixed public password [1,2,3]; never use this adapter for user passwords.
//! The end-to-end trust anchor remains the pinned TLS certificate.
use crate::crypto::direct::Error;
use crypto_bigint::{
    Encoding, U256, impl_modulus,
    modular::constant_mod::{Residue, ResidueParams},
};
use num_bigint::BigUint;
use serde::{Deserialize, Serialize};
use serde_json::Number;
use sha2::{Digest, Sha256};
use subtle::{Choice, ConditionallySelectable, ConstantTimeEq};
use zeroize::Zeroizing;

impl_modulus!(
    Prime,
    U256,
    "4000000000000000000000000200104080000000000000000004004103082041"
);
type F = Residue<Prime, { U256::LIMBS }>;
const ORDER: U256 =
    U256::from_be_hex("4000000000000000000000000200103F800000000000000000040040FF07FFC1");

// Jacobian coordinates; infinity has Z=0. Field arithmetic uses crypto-bigint.
#[derive(Clone, Copy)]
struct Point {
    x: F,
    y: F,
    z: F,
}
impl Point {
    const ID: Self = Self {
        x: F::ZERO,
        y: F::ONE,
        z: F::ZERO,
    };
    fn select(a: Self, b: Self, choice: Choice) -> Self {
        Self {
            x: F::conditional_select(&a.x, &b.x, choice),
            y: F::conditional_select(&a.y, &b.y, choice),
            z: F::conditional_select(&a.z, &b.z, choice),
        }
    }
    fn affine(x: U256, y: U256) -> Result<Self, Error> {
        if x >= Prime::MODULUS || y >= Prime::MODULUS {
            return Err("relay coordinate out of range".into());
        }
        let p = Self {
            x: F::new(&x),
            y: F::new(&y),
            z: F::ONE,
        };
        if p.y * p.y != p.x * p.x * p.x + F::new(&U256::from(19u8)) {
            return Err("relay point is not on SIEC255".into());
        }
        Ok(p)
    }
    fn xy(self) -> Result<(U256, U256), Error> {
        if bool::from(self.z.ct_eq(&F::ZERO)) {
            return Err("relay point at infinity".into());
        }
        let zi = self.z.invert().0;
        Ok((
            (self.x * zi * zi).retrieve(),
            (self.y * zi * zi * zi).retrieve(),
        ))
    }
    fn double(self) -> Self {
        // dbl-2009-l for a=0.
        let a = self.x * self.x;
        let b = self.y * self.y;
        let c = b * b;
        let d0 = (self.x + b) * (self.x + b) - a - c;
        let d = d0 + d0;
        let e = a + a + a;
        let x = e * e - d - d;
        let c8 = c + c + c + c + c + c + c + c;
        Self {
            x,
            y: e * (d - x) - c8,
            z: (self.y + self.y) * self.z,
        }
    }
    fn add(self, other: Self) -> Self {
        // add-2007-bl with branchless exceptional-case selection.
        let z1 = self.z * self.z;
        let z2 = other.z * other.z;
        let u1 = self.x * z2;
        let u2 = other.x * z1;
        let s1 = self.y * other.z * z2;
        let s2 = other.y * self.z * z1;
        let h = u2 - u1;
        let i = (h + h) * (h + h);
        let j = h * i;
        let r = s2 - s1 + s2 - s1;
        let v = u1 * i;
        let x = r * r - j - v - v;
        let result = Self {
            x,
            y: r * (v - x) - (s1 + s1) * j,
            z: ((self.z + other.z) * (self.z + other.z) - z1 - z2) * h,
        };
        let result = Self::select(result, Self::ID, u1.ct_eq(&u2));
        let result = Self::select(result, self.double(), u1.ct_eq(&u2) & s1.ct_eq(&s2));
        let result = Self::select(result, other, self.z.ct_eq(&F::ZERO));
        Self::select(result, self, other.z.ct_eq(&F::ZERO))
    }
    fn neg(self) -> Self {
        Self {
            y: F::ZERO - self.y,
            ..self
        }
    }
    fn mul(self, scalar: &[u8]) -> Self {
        let mut result = Self::ID;
        for byte in scalar {
            for bit in (0..8).rev() {
                let doubled = result.double();
                result = Self::select(doubled, doubled.add(self), Choice::from((byte >> bit) & 1));
            }
        }
        result
    }
}
fn bases() -> (Point, Point, Point) {
    let g = Point::affine(U256::from(5u8), U256::from(12u8)).unwrap();
    let u = Point::affine(
        U256::from_be_hex("0000000000000000000000008AED73AF1C28FFE0E075B724A9B5C218A86BFAAD"),
        U256::from_be_hex("28CF5F19517BDDDBAAB494FC68B205BC5407DF281C4DE9E272273C3E259673F3"),
    )
    .unwrap();
    let v = Point::affine(
        U256::from_be_hex("000000000000000000000000BE58A717B83350798221BE18B2C142F2598B2531"),
        U256::from_be_hex("2B5187E35B6AC168383B5EC992D29426207F6F522F5244421C16D67EB2C63F5F"),
    )
    .unwrap();
    (g, u, v)
}
fn number(n: U256) -> Number {
    BigUint::from_bytes_be(&n.to_be_bytes())
        .to_str_radix(10)
        .parse()
        .unwrap()
}
fn coordinate(n: &Number) -> Result<U256, Error> {
    let s = n.to_string();
    if s.len() > 77 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid relay coordinate".into());
    }
    let n = BigUint::parse_bytes(s.as_bytes(), 10)
        .ok_or("invalid relay coordinate")?
        .to_bytes_be();
    if n.len() > 32 {
        return Err("relay coordinate overflow".into());
    }
    let mut b = [0; 32];
    b[32 - n.len()..].copy_from_slice(&n);
    Ok(U256::from_be_bytes(b))
}
#[derive(Serialize, Deserialize)]
struct Wire {
    #[serde(rename = "Role")]
    role: u8,
    #[serde(rename = "Uᵤ")]
    ux: Option<Number>,
    #[serde(rename = "Uᵥ")]
    uy: Option<Number>,
    #[serde(rename = "Vᵤ")]
    vx: Option<Number>,
    #[serde(rename = "Vᵥ")]
    vy: Option<Number>,
    #[serde(rename = "Xᵤ")]
    xx: Option<Number>,
    #[serde(rename = "Xᵥ")]
    xy: Option<Number>,
    #[serde(rename = "Yᵤ")]
    yx: Option<Number>,
    #[serde(rename = "Yᵥ")]
    yy: Option<Number>,
}
pub(super) struct Client {
    scalar: Zeroizing<[u8; 32]>,
    x: Point,
}
impl Client {
    pub fn start() -> Result<(Self, Vec<u8>), Error> {
        let mut scalar = Zeroizing::new([0; 32]);
        loop {
            getrandom::fill(scalar.as_mut()).map_err(|e| format!("random source: {e}"))?;
            let n = U256::from_be_bytes(*scalar);
            if n != U256::ZERO && n < ORDER {
                break;
            }
        }
        Self::from_scalar(scalar)
    }
    fn from_scalar(scalar: Zeroizing<[u8; 32]>) -> Result<(Self, Vec<u8>), Error> {
        let (g, u, v) = bases();
        let x = u.mul(&[1, 2, 3]).add(g.mul(scalar.as_ref()));
        let (ux, uy) = u.xy()?;
        let (vx, vy) = v.xy()?;
        let (xx, xy) = x.xy()?;
        let wire = Wire {
            role: 0,
            ux: Some(number(ux)),
            uy: Some(number(uy)),
            vx: Some(number(vx)),
            vy: Some(number(vy)),
            xx: Some(number(xx)),
            xy: Some(number(xy)),
            yx: None,
            yy: None,
        };
        Ok((Self { scalar, x }, serde_json::to_vec(&wire)?))
    }
    pub fn finish(self, bytes: &[u8]) -> Result<Zeroizing<[u8; 32]>, Error> {
        let wire: Wire = serde_json::from_slice(bytes)?;
        if wire.role != 1 {
            return Err("unexpected relay PAKE role".into());
        }
        let y = Point::affine(
            coordinate(wire.yx.as_ref().ok_or("missing relay Y")?)?,
            coordinate(wire.yy.as_ref().ok_or("missing relay Y")?)?,
        )?;
        // Reject points outside the expected subgroup before scalar multiplication.
        if !bool::from(y.mul(&ORDER.to_be_bytes()).z.ct_eq(&F::ZERO)) {
            return Err("invalid relay subgroup".into());
        }
        let z = y
            .add(bases().2.mul(&[1, 2, 3]).neg())
            .mul(self.scalar.as_ref());
        let mut hash = Sha256::new();
        hash.update([1, 2, 3]);
        for point in [self.x, y, z] {
            let (x, y) = point.xy()?;
            for n in [x, y] {
                let bytes = Zeroizing::new(n.to_be_bytes());
                let first = bytes.iter().position(|b| *b != 0).unwrap_or(32);
                hash.update(&bytes[first..]); // Go big.Int.Bytes: minimal big-endian bytes.
            }
        }
        Ok(Zeroizing::new(hash.finalize().into()))
    }
}

#[cfg(test)]
pub(super) fn fixture_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}

#[cfg(test)]
pub(super) fn server_reply(bytes: &[u8]) -> (Vec<u8>, Zeroizing<[u8; 32]>) {
    let mut wire: Wire = serde_json::from_slice(bytes).unwrap();
    assert_eq!(wire.role, 0);
    let x = Point::affine(
        coordinate(wire.xx.as_ref().unwrap()).unwrap(),
        coordinate(wire.xy.as_ref().unwrap()).unwrap(),
    )
    .unwrap();
    let (g, u, v) = bases();
    let mut beta = Zeroizing::new([0; 32]);
    beta[31] = 31;
    let y = v.mul(&[1, 2, 3]).add(g.mul(beta.as_ref()));
    let z = x.add(u.mul(&[1, 2, 3]).neg()).mul(beta.as_ref());
    let (yx, yy) = y.xy().unwrap();
    wire.role = 1;
    wire.yx = Some(number(yx));
    wire.yy = Some(number(yy));
    let mut hash = Sha256::new();
    hash.update([1, 2, 3]);
    for point in [x, y, z] {
        let (x, y) = point.xy().unwrap();
        for n in [x, y] {
            let bytes = n.to_be_bytes();
            let first = bytes.iter().position(|b| *b != 0).unwrap_or(32);
            hash.update(&bytes[first..]);
        }
    }
    (
        serde_json::to_vec(&wire).unwrap(),
        Zeroizing::new(hash.finalize().into()),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn go_affine_oracle_matches_wire_and_session_key() {
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/relay-v11.5.3.json")).unwrap();
        let scalar = fixture_hex(fixture["scalar"].as_str().unwrap())
            .try_into()
            .unwrap();
        let (client, hello) = Client::from_scalar(Zeroizing::new(scalar)).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&hello).unwrap(),
            fixture["client"]
        );
        let key = client
            .finish(&serde_json::to_vec(&fixture["server"]).unwrap())
            .unwrap();
        assert_eq!(key.as_ref(), fixture_hex(fixture["key"].as_str().unwrap()));
    }
    #[test]
    fn group_laws_and_invalid_points() {
        let (g, u, v) = bases();
        for p in [g, u, v] {
            assert!(bool::from(p.mul(&ORDER.to_be_bytes()).z.ct_eq(&F::ZERO)));
            assert!(bool::from(p.add(p.neg()).z.ct_eq(&F::ZERO)));
            assert_eq!(p.mul(&[2]).xy().unwrap(), p.add(p).xy().unwrap());
            assert_eq!(p.mul(&[3]).xy().unwrap(), p.add(p).add(p).xy().unwrap());
        }
        assert!(Point::affine(Prime::MODULUS, U256::ONE).is_err());
        assert!(Point::affine(U256::ZERO, U256::ZERO).is_err());
        let fixture: serde_json::Value =
            serde_json::from_str(include_str!("../../tests/fixtures/relay-v11.5.3.json")).unwrap();
        for field in ["Role", "Yᵤ", "Yᵥ"] {
            let (client, _) = Client::start().unwrap();
            let mut reply = fixture["server"].clone();
            reply[field] = serde_json::json!(0);
            assert!(client.finish(&serde_json::to_vec(&reply).unwrap()).is_err());
        }
    }
}

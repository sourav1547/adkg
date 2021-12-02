// `clippy` is a code linting tool for improving code quality by catching
// common mistakes or strange code patterns. If the `cargo-clippy` feature
// is provided, all compiler warnings are prohibited.
#![cfg_attr(feature = "cargo-clippy", deny(warnings))]
#![cfg_attr(feature = "cargo-clippy", allow(inline_always))]
#![cfg_attr(feature = "cargo-clippy", allow(too_many_arguments))]
#![cfg_attr(feature = "cargo-clippy", allow(unreadable_literal))]
#![cfg_attr(feature = "cargo-clippy", allow(many_single_char_names))]
#![cfg_attr(feature = "cargo-clippy", allow(new_without_default_derive))]
#![cfg_attr(feature = "cargo-clippy", allow(write_literal))]
// Force public structures to implement Debug
#![deny(missing_debug_implementations)]

#![feature(specialization)]
#[macro_use]
extern crate pyo3;

use pyo3::prelude::*;
use pyo3::types::PyList;
use pyo3::types::PyBool;
use pyo3::types::PyBytes;
use pyo3::types::PyLong;
use pyo3::PyNumberProtocol;
use pyo3::basic::CompareOp;
use pyo3::PyErr;
use pyo3::exceptions;
//mod number;
//use self::number::PyNumberProtocol;
use pyo3::PyObjectProtocol;
use std::convert::TryFrom;
use std::convert::TryInto;

extern crate num_bigint;
use num_bigint::{BigInt, Sign};

extern crate num_traits;
use num_traits::cast::ToPrimitive;
use num_traits::Pow;
use num_traits::Num;

extern crate byteorder;
extern crate ff;
extern crate sha2;
extern crate hex;
extern crate group;
extern crate rand_core;
extern crate rand_chacha;



#[cfg(test)]
pub mod tests;

pub mod bls12_381;
use bls12_381::{G1, G1Affine, G1Compressed, G2, Fr, Fq, Fq2, Fq6, Fq12, FqRepr, FrRepr};
use group::CurveProjective;
use group::CurveAffine;
use group::EncodedPoint;

use ff::{Field,  PrimeField, PrimeFieldDecodingError, PrimeFieldRepr, ScalarEngine, SqrtField};
use std::error::Error;
use std::fmt;
use std::io::{self, Write};
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use sha2::{Sha256, Sha512, Digest};
extern crate curve25519_dalek;
//pub mod curve25519_dalek;
use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::RistrettoPoint;
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::traits::{Identity, VartimeMultiscalarMul};
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::backend::serial::curve_models::{
    AffineNielsPoint, CompletedPoint, ProjectiveNielsPoint, ProjectivePoint,
};
use std::ops::MulAssign;
use std::ops::AddAssign;
use std::ops::SubAssign;
use std::ops::Neg;
extern crate num_integer;
use num_integer::Integer;


fn hex_to_bin (hexstr: &String) -> String
{
    let mut out = String::from("");
    let mut bin = "";
    //Ignore the 0x at the beginning
    let mut searchstr = "";
    if hexstr.as_bytes()[1] as char == 'x'{
        searchstr = &hexstr[2..];
    }
    else{
        searchstr = hexstr;
    }
    for c in searchstr.chars()
    {
        match c
        {
            '0' => bin = "0000",
            '1' => bin = "0001",
            '2' => bin = "0010",
            '3' => bin = "0011",
            '4' => bin = "0100",
            '5' => bin = "0101",
            '6' => bin = "0110",
            '7' => bin = "0111",
            '8' => bin = "1000",
            '9' => bin = "1001",
            'A'|'a' => bin = "1010",
            'B'|'b' => bin = "1011",
            'C'|'c' => bin = "1100",
            'D'|'d' => bin = "1101",
            'E'|'e' => bin = "1110",
            'F'|'f' => bin = "1111",
            _ => bin = ""
        }
        out.push_str(bin);
    }
    out
}


//We are currently using pairing v 0.16.0. The code is copied here rather than imported so that
//some private struct fields can be manipulated.
//*************** BEGIN CODE BORROWED FROM PAIRING CRATE **************
pub trait Engine: ScalarEngine {
    /// The projective representation of an element in G1.
    type G1: CurveProjective<
            Engine = Self,
            Base = Self::Fq,
            Scalar = Self::Fr,
            Affine = Self::G1Affine,
        > + From<Self::G1Affine>;

    /// The affine representation of an element in G1.
    type G1Affine: PairingCurveAffine<
            Engine = Self,
            Base = Self::Fq,
            Scalar = Self::Fr,
            Projective = Self::G1,
            Pair = Self::G2Affine,
            PairingResult = Self::Fqk,
        > + From<Self::G1>;

    /// The projective representation of an element in G2.
    type G2: CurveProjective<
            Engine = Self,
            Base = Self::Fqe,
            Scalar = Self::Fr,
            Affine = Self::G2Affine,
        > + From<Self::G2Affine>;

    /// The affine representation of an element in G2.
    type G2Affine: PairingCurveAffine<
            Engine = Self,
            Base = Self::Fqe,
            Scalar = Self::Fr,
            Projective = Self::G2,
            Pair = Self::G1Affine,
            PairingResult = Self::Fqk,
        > + From<Self::G2>;

    /// The base field that hosts G1.
    type Fq: PrimeField + SqrtField;

    /// The extension field that hosts G2.
    type Fqe: SqrtField;

    /// The extension field that hosts the target group of the pairing.
    type Fqk: Field;

    /// Perform a miller loop with some number of (G1, G2) pairs.
    fn miller_loop<'a, I>(i: I) -> Self::Fqk
    where
        I: IntoIterator<
            Item = &'a (
                &'a <Self::G1Affine as PairingCurveAffine>::Prepared,
                &'a <Self::G2Affine as PairingCurveAffine>::Prepared,
            ),
        >;

    /// Perform final exponentiation of the result of a miller loop.
    fn final_exponentiation(_: &Self::Fqk) -> Option<Self::Fqk>;

    /// Performs a complete pairing operation `(p, q)`.
    fn pairing<G1, G2>(p: G1, q: G2) -> Self::Fqk
    where
        G1: Into<Self::G1Affine>,
        G2: Into<Self::G2Affine>,
    {
        Self::final_exponentiation(&Self::miller_loop(
            [(&(p.into().prepare()), &(q.into().prepare()))].iter(),
        ))
        .unwrap()
    }
}

/// Affine representation of an elliptic curve point that can be used
/// to perform pairings.
pub trait PairingCurveAffine: CurveAffine {
    type Prepared: Clone + Send + Sync + 'static;
    type Pair: PairingCurveAffine<Pair = Self>;
    type PairingResult: Field;

    /// Prepares this element for pairing purposes.
    fn prepare(&self) -> Self::Prepared;

    /// Perform a pairing
    fn pairing_with(&self, other: &Self::Pair) -> Self::PairingResult;
}


//*************** END CODE BORROWED FROM PAIRING CRATE **************

#[pyclass(module = "pypairing", name = G1)]
#[derive(Clone)]
struct PyG1 {
   g1 : G1,
   pp : Vec<G1>,
   pplevel : usize
}

#[pymethods]
impl PyG1 {

    #[new]
    fn new() -> Self {
        let g =  G1::one();
        PyG1{
            g1: g,
            pp: Vec::new(),
            pplevel : 0
        }
    }

    fn randomize(&mut self, a: Vec<u32>) -> PyResult<()>{
        let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
        let mut i = 0;
        for item in a.iter(){
            let myu32: &u32 = item;
            seed[i] = *myu32;
            i = i + 1;
        }
        let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
        let g = G1::random(&mut rng);
        self.g1 = g;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn load_fq_proj(&mut self, fqx: &PyFq, fqy: &PyFq, fqz: &PyFq) -> PyResult<()> {
        //self.g1.x = fqx.fq;
        //self.g1.y = fqy.fq;
        //self.g1.z = fqz.fq;
        self.g1 = G1 {
            x: fqx.fq,
            y: fqy.fq,
            z: fqz.fq,
        };
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn load_fq_affine(&mut self, fqx: &PyFq, fqy: &PyFq) -> PyResult<()> {
        //let mut a = self.g1.into_affine();
        //a.x = fqx.fq;
        //a.y = fqy.fq;
        //self.g1 = a.into_projective();
        let ga = G1Affine {
            x: fqx.fq,
            y: fqy.fq,
            infinity: false
        };
        self.g1 = ga.into_projective();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn py_pairing_with(&self, g2: &PyG2, r: &mut PyFq12) -> PyResult<()> {
        let a = self.g1.into_affine();
        let b = g2.g2.into_affine();
        r.fq12 = a.pairing_with(&b);
        Ok(())
    }

    fn one(&mut self) -> PyResult<()> {
        self.g1 = G1::one();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn zero(&mut self) -> PyResult<()> {
        self.g1 = G1::zero();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn double(&mut self) -> PyResult<()> {
        self.g1.double();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn negate(&mut self) -> PyResult<()> {
        self.g1.negate();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn affine_negate(&mut self) -> PyResult<()> {
        let mut a = self.g1.into_affine();
        a.negate();
        self.g1 = a.into_projective();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn add_assign(&mut self, other: &PyG1) -> PyResult<()> {
        self.g1.add_assign(&other.g1);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    

    fn sub_assign(&mut self, other: &PyG1) -> PyResult<()> {
        self.g1.sub_assign(&other.g1);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    //Keeping previous code for multithreading in case it comes in handy
    //fn mul_assign(&mut self, py: Python, other:&PyFr) -> PyResult<()> {
    fn mul_assign(&mut self, other:&PyFr) -> PyResult<()>{
        //py.allow_threads(move || self.g1.mul_assign(other.fr));
        self.g1.mul_assign(other.fr);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    /// a.equals(b)
    fn equals(&self, other: &PyG1) -> bool {
        self.g1 == other.g1
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyG1) -> PyResult<()> {
        self.g1 = other.g1;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    pub fn projective(&self) -> PyResult<String> {
        //Ok(format!("({}, {}, {})",self.g1.x, self.g1.y, self.g1.z))
        Ok(format!("({}, {}, {})",self.g1.x, self.g1.y, self.g1.z))
    }

    pub fn __str__(&self) -> PyResult<String> {
        let aff = self.g1.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
        //Ok(format!("({}, {})",self.g1.into_affine().x, self.g1.into_affine().y))
    }
    
    //Serialize into affine coordinates so that equal points serialize the same
    pub fn __getstate__<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        let aff = self.g1.into_affine();
        let compressed = aff.into_compressed();
        Ok(PyBytes::new(py, compressed.as_ref()))
        /*let fqx = FqRepr::from(aff.x);
        let fqy = FqRepr::from(aff.y);
        let arr1: &[u64] = fqx.as_ref();
        let arr2: &[u64] = fqy.as_ref();
        let mut end: [u64;1] = [0;1];
        if aff.infinity {
            end[0] = 1;
        }
        let arr = [arr1, arr2, &end].concat();
        let u8arr = unsafe{arr.align_to::<u8>().1};
        Ok(PyBytes::new(py, &u8arr))*/
    }
    
    pub fn __setstate__(&mut self, list: &PyAny) -> PyResult<()>
    {
        //let arr: [u64; 13] = list.extract()?;
        let u8arr: &[u8] = list.extract()?;
        let bytes: [u8;48] = u8arr.try_into().expect("invalid initialization");
        let compressed = G1Compressed(bytes);
        let aff = compressed.into_affine().unwrap();
        self.g1 = aff.into_projective();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
        /*let arr = unsafe{u8arr.align_to::<u64>().1};
        let fqxr = FqRepr(arr[0..6].try_into().expect("invalid initialization"));
        let fqyr = FqRepr(arr[6..12].try_into().expect("invalid initialization"));
        let fqx = Fq::from_repr(fqxr).unwrap();
        let fqy = Fq::from_repr(fqyr).unwrap();
        //There may be a more compact way to do this
        let inf = arr[12] == 1;
        let ga = G1Affine {
            x: fqx,
            y: fqy,
            infinity: inf
        };
        self.g1 = ga.into_projective();
        Ok(())*/
    }
    
    //Creates preprocessing elements to allow fast scalar multiplication.
    //Level determines extent of precomputation
    fn preprocess(&mut self, level: usize) -> PyResult<()> {
        self.pplevel = level;
        //Everything requires a different kind of int (and only works with that kind)
        let mut base: u64 = 2;
        //calling pow on a u64 only accepts a u32 parameter for reasons undocumented
        base = base.pow(level as u32);
        let ppsize = (base - 1) * ((255 + level as u64 - 1)/(level as u64));
        self.pp = Vec::with_capacity(ppsize as usize);
        //FrRepr::from only takes a u64
        let factor = Fr::from_repr(FrRepr::from(base)).unwrap();
        self.pp.push(self.g1.clone());
        for i in 1..base-1
        {
            //Yes, I really need to expicitly cast the indexing variable...
            let mut next = self.pp[i as usize -1].clone();
            next.add_assign(&self.g1);
            self.pp.push(next);
        }
        //(x + y - 1) / y is a way to round up the integer division x/y
        for i in base-1..(base - 1) * ((255 + level as u64 - 1)/(level as u64)) {
            let mut next = self.pp[i as usize - (base-1) as usize].clone();
            //Wait, so add_assign takes a borrowed object but mul_assign doesn't?!?!?!?
            next.mul_assign(factor);
            self.pp.push(next);
        }
        //It's not really Ok. This is terrible.
        Ok(())
    }
 
    fn ppmul(&self, prodend: &PyFr, out: &mut PyG1) -> PyResult<()>
    {
        if self.pp.len() == 0
        {
            out.g1 = self.g1.clone();
            out.g1.mul_assign(prodend.fr);
        }
        else
        {
            let zero = Fr::from_repr(FrRepr::from(0)).unwrap();
            out.g1.mul_assign(zero);
            let hexstr = format!("{}", prodend.fr);
            let binstr = hex_to_bin(&hexstr);
            let mut buffer = 0usize;
            for (i, c) in binstr.chars().rev().enumerate()
            {
                if i%self.pplevel == 0 && buffer != 0
                {
                    //(2**level - 1)*(i/level - 1) + (buffer - 1)
                    out.g1.add_assign(&self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)]);
                    buffer = 0;
                }
                if c == '1'
                {
                    buffer = buffer + 2usize.pow((i%self.pplevel) as u32);
                }
            }
        }
        Ok(())
    }
    
    fn get_pplevel(&self) -> PyResult<usize> {
        Ok(self.pplevel)
    }

    fn pow(&self, rhs: &PyAny)  -> PyResult<PyG1> {
        let mut out = PyG1{
            g1: G1::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            let pyfrexp = bigint_to_pyfr(&exp);
            self.ppmul(&pyfrexp, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyFr = &rhscel.as_ref().unwrap().borrow();
            self.ppmul(&exp, &mut out).unwrap();
        }
        Ok(out)
    }

    #[staticmethod]
    fn hash(bytestr: &PyBytes) -> PyResult<PyG1>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let g = G1::random(&mut rng);
        Ok(PyG1{
            g1: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn hash_many(bytestr: &PyBytes, length: usize) -> PyResult<Vec<PyG1>>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = Vec::with_capacity(length);
        for i in 0..length{
            let g = G1::random(&mut rng);
            out.push(PyG1{
                g1: g,
                pp: Vec::new(),
                pplevel : 0
            });
        }
        Ok(out)
    }
    
    #[staticmethod]
    fn identity() -> PyResult<PyG1> {
        let g =  G1::zero();
        Ok(PyG1{
            g1: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn rand(a: Option<Vec<u32>>) -> PyResult<PyG1> {
        match a {
            None => {
                let mut rng = ChaCha20Rng::from_entropy();
                let g = G1::random(&mut rng);
                Ok(PyG1{
                    g1: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            },
            Some(a) => {
                let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
                let mut i = 0;
                for item in a.iter(){
                    let myu32: &u32 = item;
                    seed[i] = *myu32;
                    i = i + 1;
                }
                let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
                let g = G1::random(&mut rng);
                Ok(PyG1{
                    g1: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            }
        }
        
    }
}

#[pyproto]
impl PyNumberProtocol for PyG1 {
    fn __mul__(lhs: PyG1, rhs: PyG1) -> PyResult<PyG1> {
        let mut out = PyG1{
            g1: G1::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        out.g1.clone_from(&lhs.g1);
        out.g1.add_assign(&rhs.g1);
        Ok(out)
    }
    fn __imul__(&mut self, other: PyG1) -> PyResult<()> {
        self.add_assign(&other)?;
        Ok(())
    }
    // Somehow this is faster AND more general? Hell yeah!
    fn __pow__(lhs: PyG1, rhs: &PyAny, _mod: Option<&'p PyAny>)  -> PyResult<PyG1> {
        let mut out = PyG1{
            g1: G1::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            let pyfrexp = bigint_to_pyfr(&exp);
            lhs.ppmul(&pyfrexp, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyFr = &rhscel.as_ref().unwrap().borrow();
            lhs.ppmul(&exp, &mut out).unwrap();
        }
        Ok(out)
    }
    /*fn __pow__(lhs: PyG1, rhs: PyFr, _mod: Option<&'p PyAny>)  -> PyResult<PyG1> {
        let mut out = PyG1{
            g1: G1::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        lhs.ppmul(&rhs, &mut out).unwrap();
        Ok(out)
    }*/
}

#[pyproto]
impl PyObjectProtocol for PyG1 {
    fn __str__(&self) -> PyResult<String> {
        let aff = self.g1.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
    }
    /*fn __repr__(&self) -> PyResult<String> {
        let aff = self.g1.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
        //Ok(format!("({}, {})",self.g1.into_affine().x, self.g1.into_affine().y))
    }*/
    fn __repr__(&self) -> PyResult<String> {
        let aff = self.g1.into_affine();
        let hex1 = aff.x.to_string();
        let hex2 = aff.y.to_string();
        let bi1 = BigInt::from_str_radix(&hex1[5..hex1.len()-1], 16).unwrap();
        let bi2 = BigInt::from_str_radix(&hex2[5..hex2.len()-1], 16).unwrap();
        Ok(format!("({}, {})",bi1.to_str_radix(10), bi2.to_str_radix(10)))
    }
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyG1 ,b: &PyAny| {
            let othercel = &b.downcast::<PyCell<PyG1>>();
            if othercel.is_err(){
                false
            }
            else{
                let otherg1: &PyG1 = &othercel.as_ref().unwrap().borrow();
                a.g1 == otherg1.g1
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
}

#[pyclass(module = "pypairing", name = G2)]
#[derive(Clone)]
struct PyG2 {
   g2 : G2,
   pp : Vec<G2>,
   pplevel : usize
}

#[pymethods]
impl PyG2 {

    #[new]
    fn new() -> Self {
        let g =  G2::one();
        PyG2{
            g2: g,
            pp: Vec::new(),
            pplevel : 0
        }
    }

    fn randomize(&mut self, a: Vec<u32>) -> PyResult<()>{
        let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
        let mut i = 0;
        for item in a.iter(){
            let myu32: &u32 = item;
            seed[i] = *myu32;
            i = i + 1;
        }
        let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
        let g = G2::random(&mut rng);
        self.g2 = g;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn load_fq_proj(&mut self, fq2x: &PyFq2, fq2y: &PyFq2, fq2z: &PyFq2) -> PyResult<()> {
        self.g2.x = fq2x.fq2;
        self.g2.y = fq2y.fq2;
        self.g2.z = fq2z.fq2;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn load_fq_affine(&mut self, fq2x: &PyFq2, fq2y: &PyFq2) -> PyResult<()> {
        let mut a = self.g2.into_affine();
        a.x = fq2x.fq2;
        a.y = fq2y.fq2;
        self.g2 = a.into_projective();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn py_pairing_with(&self, g1: &PyG1, r: &mut PyFq12) -> PyResult<()> {
        let a = self.g2.into_affine();
        let b = g1.g1.into_affine();
        r.fq12 = a.pairing_with(&b);
        Ok(())
    }

    fn one(&mut self) -> PyResult<()> {
        self.g2 = G2::one();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn zero(&mut self) -> PyResult<()> {
        self.g2 = G2::zero();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn double(&mut self) -> PyResult<()> {
        self.g2.double();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn negate(&mut self) -> PyResult<()> {
        self.g2.negate();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn affine_negate(&mut self) -> PyResult<()> {
        let mut a = self.g2.into_affine();
        a.negate();
        self.g2 = a.into_projective();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn add_assign(&mut self, other: &PyG2) -> PyResult<()> {
        self.g2.add_assign(&other.g2);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn sub_assign(&mut self, other: &PyG2) -> PyResult<()> {
        self.g2.sub_assign(&other.g2);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn mul_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.g2.mul_assign(other.fr);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
    fn pow(&self, rhs: &PyAny)  -> PyResult<PyG2> {
        let mut out = PyG2{
            g2: G2::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            let pyfrexp = bigint_to_pyfr(&exp);
            self.ppmul(&pyfrexp, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyFr = &rhscel.as_ref().unwrap().borrow();
            self.ppmul(&exp, &mut out).unwrap();
        }
        Ok(out)
    }

    /// a.equals(b)
    fn equals(&self, other: &PyG2) -> bool {
        self.g2 == other.g2
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyG2) -> PyResult<()> {
        self.g2 = other.g2;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    pub fn projective(&self) -> PyResult<String> {
        Ok(format!("({}, {}, {})",self.g2.x, self.g2.y, self.g2.z))
    }
    
    pub fn __str__(&self) -> PyResult<String> {
        let aff = self.g2.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
        //Ok(format!("({}, {})",self.g2.into_affine().x, self.g2.into_affine().y))
    }
    
    fn preprocess(&mut self, level: usize) -> PyResult<()> {
        self.pplevel = level;
        let mut base: u64 = 2;
        base = base.pow(level as u32);
        let ppsize = (base as usize - 1) * (255 + level - 1)/(level);
        self.pp = Vec::with_capacity(ppsize);
        let factor = Fr::from_repr(FrRepr::from(base)).unwrap();
        self.pp.push(self.g2.clone());
        for i in 1..base-1
        {
            let mut next = self.pp[i as usize -1].clone();
            next.add_assign(&self.g2);
            self.pp.push(next);
        }
        //(x + y - 1) / y is a way to round up the integer division x/y
        for i in base-1..(base - 1) * (255 + level as u64 - 1)/(level as u64) {
            let mut next = self.pp[i as usize - (base-1) as usize].clone();
            next.mul_assign(factor);
            self.pp.push(next);
        }
        Ok(())
    }
    fn ppmul(&self, prodend: &PyFr, out: &mut PyG2) -> PyResult<()>
    {
        if self.pp.len() == 0
        {
            out.g2 = self.g2.clone();
            out.g2.mul_assign(prodend.fr);
        }
        else
        {
            let zero = Fr::from_repr(FrRepr::from(0)).unwrap();
            out.g2.mul_assign(zero);
            let hexstr = format!("{}", prodend.fr);
            let binstr = hex_to_bin(&hexstr);
            let mut buffer = 0usize;
            for (i, c) in binstr.chars().rev().enumerate()
            {
                if i%self.pplevel == 0 && buffer != 0
                {
                    //(2**level - 1)*(i/level - 1) + (buffer - 1)
                    out.g2.add_assign(&self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)]);
                    buffer = 0;
                }
                if c == '1'
                {
                    buffer = buffer + 2usize.pow((i%self.pplevel) as u32);
                }
            }
        }
        Ok(())
    }
    
    #[staticmethod]
    fn hash(bytestr: &PyBytes) -> PyResult<PyG2>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let g = G2::random(&mut rng);
        Ok(PyG2{
            g2: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn hash_many(bytestr: &PyBytes, length: usize) -> PyResult<Vec<PyG2>>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = Vec::with_capacity(length);
        for i in 0..length{
            let g = G2::random(&mut rng);
            out.push(PyG2{
                g2: g,
                pp: Vec::new(),
                pplevel : 0
            });
        }
        Ok(out)
    }
    
    #[staticmethod]
    fn identity() -> PyResult<PyG2> {
        let g =  G2::zero();
        Ok(PyG2{
            g2: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn rand(a: Option<Vec<u32>>) -> PyResult<PyG2> {
        match a {
            None => {
                let mut rng = ChaCha20Rng::from_entropy();
                let g = G2::random(&mut rng);
                Ok(PyG2{
                    g2: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            },
            Some(a) => {
                let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
                let mut i = 0;
                for item in a.iter(){
                    let myu32: &u32 = item;
                    seed[i] = *myu32;
                    i = i + 1;
                }
                let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
                let g = G2::random(&mut rng);
                Ok(PyG2{
                    g2: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            }
        }
        
    }

}

#[pyproto]
impl PyNumberProtocol for PyG2 {
    fn __mul__(lhs: PyG2, rhs: PyG2) -> PyResult<PyG2> {
        let mut out = PyG2{
            g2: G2::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        out.g2.clone_from(&lhs.g2);
        out.g2.add_assign(&rhs.g2);
        Ok(out)
    }
    fn __imul__(&mut self, other: PyG2) -> PyResult<()> {
        self.add_assign(&other)?;
        Ok(())
    }
    fn __pow__(lhs: PyG2, rhs: &PyAny, _mod: Option<&'p PyAny>)  -> PyResult<PyG2> {
        let mut out = PyG2{
            g2: G2::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            let pyfrexp = bigint_to_pyfr(&exp);
            lhs.ppmul(&pyfrexp, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyFr = &rhscel.as_ref().unwrap().borrow();
            lhs.ppmul(&exp, &mut out).unwrap();
        }
        Ok(out)
    }
}

#[pyproto]
impl PyObjectProtocol for PyG2 {
    fn __str__(&self) -> PyResult<String> {
        let aff = self.g2.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
    }
    fn __repr__(&self) -> PyResult<String> {
        let aff = self.g2.into_affine();
        Ok(format!("({}, {})",aff.x, aff.y))
        //Ok(format!("({}, {})",self.g1.into_affine().x, self.g1.into_affine().y))
    }
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyG2 ,b: &PyAny| {
            let othercel = &b.downcast::<PyCell<PyG2>>();
            if othercel.is_err(){
                false
            }
            else{
                let otherg2: &PyG2 = &othercel.as_ref().unwrap().borrow();
                a.g2 == otherg2.g2
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
}

//#[pyclass]
#[pyclass(module = "pypairing", name = ZR)]
#[derive(Clone)]
struct PyFr {
   fr : Fr
}

#[pymethods]
impl PyFr {

    #[new]
    fn new(s1: Option<&PyAny>, s2: Option<u64>, s3: Option<u64>, s4: Option<u64>) -> Self {
        //let f = Fr::from_repr(FrRepr([s1,s2,s3,s4])).unwrap();
        //PyFr{
        //    fr: f,
        //}
        // Allows for initialization via either [u64, u64, u64, u64] or arbitrarily-large-int
        match s1 {
            None => PyFr{fr:Fr::one()},
            Some(s1) => {
                match s2 {
                    None => pyfr_from_pyany(s1).unwrap(),
                    Some(s2) => {
                        let is1: u64 = s1.extract().unwrap();
                        PyFr{fr: Fr::from_repr(FrRepr([is1,s2,s3.unwrap(),s4.unwrap()])).unwrap()}
                    }
                }
            }
        }
    }
    
    fn one(&mut self) -> PyResult<()> {
        self.fr = Fr::one();
        Ok(())
    }

    fn zero(&mut self) -> PyResult<()> {
        self.fr = Fr::zero();
        Ok(())
    }

    fn negate(&mut self) -> PyResult<()> {
        self.fr.negate();
        Ok(())
    }

    fn inverse(&mut self) -> PyResult<()> {
        self.fr = self.fr.inverse().unwrap();
        Ok(())
    }

    fn double(&mut self) -> PyResult<()> {
        self.fr.double();
        Ok(())
    }

    fn square(&mut self) -> PyResult<()> {
        self.fr.square();
        Ok(())
    }

    fn pow(&mut self, s1: u64, s2: u64, s3: u64, s4: u64, s5: u64, s6:u64) -> PyResult<()> {
        self.fr.pow([s1,s2,s3,s4,s5,s6]);
        Ok(())
    }

    fn add_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.fr.add_assign(&other.fr);
        Ok(())
    }

    fn sub_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.fr.sub_assign(&other.fr);
        Ok(())
    }

    fn mul_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.fr.mul_assign(&other.fr);
        Ok(())
    }
    
    fn pow_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.fr = self.fr.pow(&other.fr.into_repr());
        Ok(())
    }

    fn is_zero(&self) -> bool {
        self.fr == Fr::zero()
    }

    fn equals(&self, other: &PyFr) -> bool {
        self.fr == other.fr
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyFr) -> PyResult<()> {
        self.fr = other.fr;
        Ok(())
    }

    pub fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}",self.fr))
    }
    
    pub fn __getstate__<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        let frrep = FrRepr::from(self.fr);
        let arr: &[u64] = frrep.as_ref();
        let u8arr = unsafe{arr.align_to::<u8>().1};
        Ok(PyBytes::new(py, &u8arr))
    }
    
    pub fn __setstate__(&mut self, list: &PyAny) -> PyResult<()>
    {
        let u8arr: [u8; 32] = list.extract()?;
        //let arr: [u64; 4] = list.extract()?;
        let arr = unsafe{u8arr.align_to::<u64>().1};
        let myfr = Fr::from_repr(FrRepr(arr[0..4].try_into().expect("invalid initialization"))).unwrap();
        self.fr = myfr;
        Ok(())
    }
    
    fn __eq__<'p>(&self, other: &PyAny, py: Python<'p>) -> PyResult<&'p PyBool> {
        let otherresult = pyfr_from_pyany(other);
        if otherresult.is_err(){
            Ok(PyBool::new(py, false))
        }
        else{
            let otherfr: &PyFr = &otherresult.unwrap();
            Ok(PyBool::new(py, self.fr == otherfr.fr))
        }
    }
    
    #[staticmethod]
    fn hash(bytestr: &PyBytes) -> PyResult<PyFr>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let f = Fr::random(&mut rng);
        Ok(PyFr{fr: f})
    }
    
    #[staticmethod]
    fn hash_many(bytestr: &PyBytes, length: usize) -> PyResult<Vec<PyFr>>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = Vec::with_capacity(length);
        for i in 0..length{
            let f = Fr::random(&mut rng);
            out.push(PyFr{fr: f});
        }
        Ok(out)
    }
    
    #[staticmethod]
    fn rand(a: Option<Vec<u32>>) -> PyResult<PyFr> {
        match a {
            None => {
                let mut rng = ChaCha20Rng::from_entropy();
                let f = Fr::random(&mut rng);
                Ok(PyFr{
                    fr: f
                })
            },
            Some(a) => {
                let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
                let mut i = 0;
                for item in a.iter(){
                    let myu32: &u32 = item;
                    seed[i] = *myu32;
                    i = i + 1;
                }
                let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
                let f = Fr::random(&mut rng);
                Ok(PyFr{
                    fr: f
                })
            }
        }
        
    }
    
    #[staticmethod]
    fn random(a: Option<Vec<u32>>) -> PyResult<PyFr> {
        Ok(PyFr::rand(a)?)
    }
    
    #[staticmethod]
    fn root_of_unity() -> PyResult<PyFr> {
        Ok(PyFr{
            fr: Fr::root_of_unity()
        })
    }

}

#[pyproto]
impl PyNumberProtocol for PyFr {
    
    fn __add__(lhs: PyFr, rhs: &PyAny) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&lhs.fr);
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let addend: BigInt = rhs.extract()?;
            let pyfraddend = bigint_to_pyfr(&addend);
            out.fr.add_assign(&pyfraddend.fr);
        }
        else{
            let pyfraddend: &PyFr = &rhscel.as_ref().unwrap().borrow();
            out.fr.add_assign(&pyfraddend.fr);
        }
        Ok(out)
    }
    
    fn __truediv__(lhs: PyFr, rhs: &PyAny) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&lhs.fr);
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let prodend: BigInt = rhs.extract()?;
            let pyfrprodend = bigint_to_pyfr(&prodend);
            let mut div = Fr::one();
            div.clone_from(&pyfrprodend.fr);
            div = div.inverse().unwrap();
            out.fr.mul_assign(&div);
        }
        else{
            let pyfrprodend: &PyFr = &rhscel.as_ref().unwrap().borrow();
            let mut div = Fr::one();
            div.clone_from(&pyfrprodend.fr);
            div = div.inverse().unwrap();
            out.fr.mul_assign(&div);
        }
        Ok(out)
    }
    
    fn __mul__(lhs: PyFr, rhs: &PyAny) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&lhs.fr);
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let prodend: BigInt = rhs.extract()?;
            let pyfrprodend = bigint_to_pyfr(&prodend);
            out.fr.mul_assign(&pyfrprodend.fr);
        }
        else{
            let pyfrprodend: &PyFr = &rhscel.as_ref().unwrap().borrow();
            out.fr.mul_assign(&pyfrprodend.fr);
        }
        Ok(out)
    }
    
    fn __neg__(&self) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&self.fr);
        out.fr.negate();
        Ok(out)
    }
    
    //TODO: this does not currently work in pyo3 if __mul__ is also defined. It's a current issue that will hopefully be resolved soon
    /*fn __rmul__(&self, other: &PyAny) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&self.fr);
        let rhscel = &other.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let prodend: BigInt = other.extract()?;
            let pyfrprodend = bigint_to_pyfr(&prodend);
            out.fr.mul_assign(&pyfrprodend.fr);
        }
        else{
            let pyfrprodend: &PyFr = &rhscel.as_ref().unwrap().borrow();
            out.fr.mul_assign(&pyfrprodend.fr);
        }
        Ok(out)
    }*/
    //fn __int__(&self) -> PyResult<&'p PyLong> {
    fn __int__(&self) -> PyResult<BigInt> {
        let hex = self.fr.to_string();
        let bi = BigInt::from_str_radix(&hex[5..hex.len()-1], 16).unwrap();
        //Ok(bi.to_str_radix(10))
        Ok(bi)
    }
    
    fn __pow__(lhs: PyFr, rhs: &PyAny, _mod: Option<&'p PyAny>) -> PyResult<PyFr> {
        let expi: BigInt = rhs.extract()?;
        let exp = bigint_to_pyfrexp(&expi);
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&lhs.fr);
        out.pow_assign(&exp);
        Ok(out)
    }
    
    fn __sub__(lhs: PyFr, rhs: &PyAny) -> PyResult<PyFr> {
        let mut out = PyFr{
            fr: Fr::one()
        };
        out.fr.clone_from(&lhs.fr);
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let addend: BigInt = rhs.extract()?;
            let pyfraddend = bigint_to_pyfr(&addend);
            out.fr.sub_assign(&pyfraddend.fr);
        }
        else{
            let pyfraddend: &PyFr = &rhscel.as_ref().unwrap().borrow();
            out.fr.sub_assign(&pyfraddend.fr);
        }
        Ok(out)
    }
}

#[pyproto]
impl PyObjectProtocol for PyFr {
    fn __str__(&self) -> PyResult<String> {
        //let hex = self.fr.to_string();
        //let bi = BigInt::from_str_radix(&hex[5..hex.len()-1], 16).unwrap();
        //Ok(bi.to_str_radix(10))
        Ok(format!("{}",self.fr))
    }
    fn __repr__(&self) -> PyResult<String> {
        //Ok(format!("{}",self.fr))
        let hex = self.fr.to_string();
        let bi = BigInt::from_str_radix(&hex[5..hex.len()-1], 16).unwrap();
        Ok(bi.to_str_radix(10))
    }
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyFr ,b: &PyAny| {
            let othercel = pyfr_from_pyany(b);
            if othercel.is_err(){
                false
            }
            else{
                let otherfr: &PyFr = &othercel.unwrap();
                a.fr == otherfr.fr
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            //TODO: fix the rest of these
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
}

#[pyclass]
struct PyFq {
    fq : Fq
}
 #[pymethods]
impl PyFq {
    #[new]
    fn new() -> Self {
        let f =  Fq::zero();
        PyFq{
            fq: f,
        }
    }
    fn from_repr(&mut self, py_fq_repr: &PyFqRepr) -> PyResult<()> {
        let f = Fq::from_repr(py_fq_repr.fq_repr).unwrap();
        self.fq = f;
        Ok(())
    }
}

#[pyclass]
struct PyFq2 {
    fq2 : Fq2
}
 #[pymethods]
impl PyFq2 {
    #[new]
    fn new() -> Self {
        let f =  Fq2::zero();
        PyFq2{
            fq2: f,
        }
    }
    fn from_repr(&mut self, py_fq_repr: &PyFqRepr, py_fq_repr2: &PyFqRepr) -> PyResult<()> {
        let c0 = Fq::from_repr(py_fq_repr.fq_repr).unwrap();
        let c1 = Fq::from_repr(py_fq_repr2.fq_repr).unwrap();
        self.fq2.c0 = c0;
        self.fq2.c1 = c1;
        Ok(())
    }
}

#[pyclass]
struct PyFq6 {
    fq6 : Fq6
}
 #[pymethods]
impl PyFq6 {
    #[new]
    fn new() -> Self {
        let f =  Fq6::zero();
        PyFq6{
            fq6: f,
        }
    }
}

#[pyclass]
struct PyFqRepr {
    fq_repr : FqRepr
}
 #[pymethods]
impl PyFqRepr {
     #[new]
    fn new(s1: u64, s2: u64, s3: u64, s4: u64, s5: u64, s6: u64) -> Self {
        let f = FqRepr([s1,s2,s3,s4,s5,s6]);
        PyFqRepr{
            fq_repr: f,
        }
    }
}

#[pyclass(module = "pypairing", name = GT)]
#[derive(Clone)]
struct PyFq12 {
    fq12 : Fq12,
    pp : Vec<Fq12>,
    pplevel : usize
}

#[pymethods]
impl PyFq12 {
    #[new]
    fn new() -> Self {
        let q =  Fq12::zero();
        PyFq12{
            fq12: q,
            pp: Vec::new(),
            pplevel : 0
        }
    }

    fn randomize(&mut self, a: Vec<u32>) -> PyResult<()>{
        let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
        let mut i = 0;
        for item in a.iter(){
            let myu32: &u32 = item;
            seed[i] = *myu32;
            i = i + 1;
        }
        let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
        let g = Fq12::random(&mut rng);
        self.fq12 = g;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn from_strs(&mut self, s1: &str, s2: &str, s3: &str, s4: &str, s5: &str, s6: &str, s7: &str, s8: &str, s9: &str, s10: &str, s11: &str, s12: &str) -> PyResult<()> {
        let c0 = Fq6 {
            c0: Fq2 {
                c0: Fq::from_str(s1).unwrap(),
                c1: Fq::from_str(s2).unwrap()
            },
            c1: Fq2 {
                c0: Fq::from_str(s3).unwrap(),
                c1: Fq::from_str(s4).unwrap()
            },
            c2: Fq2 {
                c0: Fq::from_str(s5).unwrap(),
                c1: Fq::from_str(s6).unwrap()
            }
        };
        let c1 = Fq6 {
            c0: Fq2 {
                c0: Fq::from_str(s7).unwrap(),
                c1: Fq::from_str(s8).unwrap()
            },
            c1: Fq2 {
                c0: Fq::from_str(s9).unwrap(),
                c1: Fq::from_str(s10).unwrap()
            },
            c2: Fq2 {
                c0: Fq::from_str(s11).unwrap(),
                c1: Fq::from_str(s12).unwrap()
            }
        };
        self.fq12.c0 = c0;
        self.fq12.c1 = c1;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    pub fn __str__(&self) -> PyResult<String> {
        Ok(format!("({} + {} * w)",self.fq12.c0, self.fq12.c1 ))
    }

    pub fn __repr__(&self) -> PyResult<String> {
        Ok(format!("({} + {} * w)",self.fq12.c0, self.fq12.c1 ))
    }

    fn add_assign(&mut self, other: &PyFq12) -> PyResult<()> {
        self.fq12.add_assign(&other.fq12);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn sub_assign(&mut self, other: &PyFq12) -> PyResult<()> {
        self.fq12.sub_assign(&other.fq12);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn mul_assign(&mut self, other: &PyFq12) -> PyResult<()> {
        self.fq12.mul_assign(&other.fq12);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
    fn pow_assign(&mut self, other: &PyFr) -> PyResult<()> {
        self.fq12 = self.fq12.pow(&other.fr.into_repr());
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
    fn inverse(&mut self) -> PyResult<()> {
        self.fq12 = self.fq12.inverse().unwrap();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn conjugate(&mut self) -> PyResult<()> {
        self.fq12.conjugate();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
    fn preprocess(&mut self, level: usize) -> PyResult<()> {
        self.pplevel = level;
        let mut base: u64 = 2;
        base = base.pow(level as u32);
        let ppsize = (base as usize - 1) * (255 + level - 1)/(level);
        self.pp = Vec::with_capacity(ppsize);
        let factor = Fr::from_repr(FrRepr::from(base)).unwrap();
        self.pp.push(self.fq12.clone());
        for i in 1..base-1
        {
            let mut next = self.pp[i as usize -1].clone();
            next.mul_assign(&self.fq12);
            self.pp.push(next);
        }
        for i in base-1..(base - 1) * (255 + level as u64 - 1)/(level as u64) {
            let mut next = self.pp[i as usize - (base-1) as usize].clone();
            //This needs to be pow lolol!!!
            next = next.pow(factor.into_repr());
            //next.mul_assign(factor);
            self.pp.push(next);
        }
        Ok(())
    }
    
    fn __eq__<'p>(&self, other: &PyAny, py: Python<'p>) -> PyResult<&'p PyBool> {
        let othercel = &other.downcast::<PyCell<PyFq12>>();
        if othercel.is_err(){
            Ok(PyBool::new(py, false))
        }
        else{
            let otherfq12: &PyFq12 = &othercel.as_ref().unwrap().borrow();
            Ok(PyBool::new(py, self.fq12 == otherfq12.fq12))
        }
    }
    
    fn pppow(&self, prodend: &PyFr, out: &mut PyFq12) -> PyResult<()>
    {
        if self.pp.len() == 0
        {
            out.fq12 = self.fq12.clone();
            //pow assign
            out.fq12 = out.fq12.pow(&prodend.fr.into_repr());
            //out.fq.mul_assign(prodend.fr);
        }
        else
        {
            let zero = Fr::from_repr(FrRepr::from(0)).unwrap();
            //powassign
            out.fq12 = out.fq12.pow(FrRepr::from(0));
            //out.fq12.mul_assign(zero);
            let hexstr = format!("{}", prodend.fr);
            let binstr = hex_to_bin(&hexstr);
            let mut buffer = 0usize;
            for (i, c) in binstr.chars().rev().enumerate()
            {
                if i%self.pplevel == 0 && buffer != 0
                {
                    //(2**level - 1)*(i/level - 1) + (buffer - 1)
                    out.fq12.mul_assign(&self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)]);
                    buffer = 0;
                }
                if c == '1'
                {
                    buffer = buffer + 2usize.pow((i%self.pplevel) as u32);
                }
            }
        }
        Ok(())
    }

    fn one(&mut self) -> PyResult<()> {
        self.fq12 = Fq12::one();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn zero(&mut self) -> PyResult<()> {
        self.fq12 = Fq12::zero();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn equals(&self, other: &PyFq12) -> bool {
        self.fq12 == other.fq12
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyFq12) -> PyResult<()> {
        self.fq12 = other.fq12;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
        #[staticmethod]
    fn rand(a: Option<Vec<u32>>) -> PyResult<PyFq12> {
        match a {
            None => {
                let mut rng = ChaCha20Rng::from_entropy();
                let fq12 = Fq12::random(&mut rng);
                Ok(PyFq12{
                    fq12: fq12,
                    pp: Vec::new(),
                    pplevel : 0
                })
            },
            Some(a) => {
                let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
                let mut i = 0;
                for item in a.iter(){
                    let myu32: &u32 = item;
                    seed[i] = *myu32;
                    i = i + 1;
                }
                let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
                let fq12 = Fq12::random(&mut rng);
                Ok(PyFq12{
                    fq12: fq12,
                    pp: Vec::new(),
                    pplevel : 0
                })
            }
        }
        
    }
}

#[pyproto]
impl PyNumberProtocol for PyFq12 {
    fn __mul__(lhs: PyFq12, rhs: PyFq12) -> PyResult<PyFq12> {
        let mut out = PyFq12{
            fq12: Fq12::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        out.fq12.clone_from(&lhs.fq12);
        out.fq12.mul_assign(&rhs.fq12);
        Ok(out)
    }
    fn __imul__(&mut self, other: PyFq12) -> PyResult<()> {
        self.mul_assign(&other);
        Ok(())
    }
    fn __pow__(lhs: PyFq12, rhs: &PyAny, _mod: Option<&'p PyAny>)  -> PyResult<PyFq12> {
        let mut out = PyFq12{
            fq12: Fq12::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        let rhscel = &rhs.downcast::<PyCell<PyFr>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            let pyfrexp = bigint_to_pyfr(&exp);
            lhs.pppow(&pyfrexp, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyFr = &rhscel.as_ref().unwrap().borrow();
            lhs.pppow(&exp, &mut out).unwrap();
        }
        Ok(out)
    }
}

#[pyproto]
impl PyObjectProtocol for PyFq12 {
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyFq12 ,b: &PyAny| {
            let othercel = &b.downcast::<PyCell<PyFq12>>();
            if othercel.is_err(){
                false
            }
            else{
                let otherfq12: &PyFq12 = &othercel.as_ref().unwrap().borrow();
                a.fq12 == otherfq12.fq12
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
}


#[pyclass(module = "pypairing", name = Curve25519G)]
#[derive(Clone)]
struct PyRistG {
   g : RistrettoPoint,
   pp : Vec<AffineNielsPoint>, //was RistrettoPoint 
   pplevel : usize
}

#[pymethods]
impl PyRistG {

    #[new]
    fn new() -> Self {
        let g =  RistrettoPoint::identity();
        PyRistG{
            g: g,
            pp: Vec::new(),
            pplevel : 0
        }
    }

    fn one(&mut self) -> PyResult<()> {
        self.g = RistrettoPoint::identity();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn negate(&mut self) -> PyResult<()> {
        self.g = self.g.neg();
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    fn add_assign(&mut self, other: &PyRistG) -> PyResult<()> {
        self.g.add_assign(&other.g);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    

    fn sub_assign(&mut self, other: &PyRistG) -> PyResult<()> {
        self.g.sub_assign(&other.g);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    //Keeping previous code for multithreading in case it comes in handy
    //fn mul_assign(&mut self, py: Python, other:&PyFr) -> PyResult<()> {
    fn mul_assign(&mut self, other:&PyRistScalar) -> PyResult<()>{
        //py.allow_threads(move || self.g1.mul_assign(other.fr));
        self.g.mul_assign(other.scalar);
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }

    /// a.equals(b)
    fn equals(&self, other: &PyRistG) -> bool {
        self.g == other.g
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyRistG) -> PyResult<()> {
        self.g = other.g;
        if self.pplevel != 0 {
            self.pp = Vec::new();
            self.pplevel = 0;
        }
        Ok(())
    }
    
    //Serialize into affine coordinates so that equal points serialize the same
    pub fn __getstate__<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        let compressed = self.g.compress();
        Ok(PyBytes::new(py, &compressed.to_bytes()))
    }
    
    pub fn __setstate__(&mut self, list: &PyAny) -> PyResult<()>
    {
        let arr: [u8; 32] = list.extract()?;
        let compressed = CompressedRistretto::from_slice(&arr);
        let decompressed = compressed.decompress().ok_or_else(|| PyErr::new::<exceptions::TypeError, _>("Invalid deserialization for Ristretto Point (expected [u8;32])"))?;
        self.g = decompressed;
        Ok(())
    }
    
    //Creates preprocessing elements to allow fast scalar multiplication.
    //Level determines extent of precomputation
    /*fn preprocess(&mut self, level: usize) -> PyResult<()> {
        self.pplevel = level;
        //Everything requires a different kind of int (and only works with that kind)
        let mut base: u64 = 2;
        //calling pow on a u64 only accepts a u32 parameter for reasons undocumented
        base = base.pow(level as u32);
        let ppsize = (base - 1) * ((252 + level as u64 - 1)/(level as u64));
        self.pp = Vec::with_capacity(ppsize as usize);
        let factor = Scalar::from(base);
        self.pp.push(self.g.clone());
        for i in 1..base-1
        {
            //Yes, I really need to expicitly cast the indexing variable...
            let mut next = self.pp[i as usize -1].clone();
            next.add_assign(&self.g);
            self.pp.push(next);
        }
        //(x + y - 1) / y is a way to round up the integer division x/y
        for i in base-1..(base - 1) * ((252 + level as u64 - 1)/(level as u64)) {
            let mut next = self.pp[i as usize - (base-1) as usize].clone();
            //Wait, so add_assign takes a borrowed object but mul_assign doesn't?!?!?!?
            next.mul_assign(factor);
            self.pp.push(next);
        }
        //It's not really Ok. This is terrible.
        Ok(())
    }
 
    fn ppmul(&self, prodend: &PyRistScalar, out: &mut PyRistG) -> PyResult<()>
    {
        if self.pp.len() == 0
        {
            out.g = self.g.clone();
            out.g.mul_assign(prodend.scalar);
        }
        else
        {
            let zero = Scalar::zero();
            out.g.mul_assign(zero);
            let mut scalarbytes = prodend.scalar.to_bytes();
            scalarbytes.reverse();
            let hexstr = hex::encode(scalarbytes);
            let binstr = hex_to_bin(&hexstr);
            let mut buffer = 0usize;
            for (i, c) in binstr.chars().rev().enumerate()
            {
                if i%self.pplevel == 0 && buffer != 0
                {
                    //(2**level - 1)*(i/level - 1) + (buffer - 1)
                    out.g.add_assign(&self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)]);
                    buffer = 0;
                }
                if c == '1'
                {
                    buffer = buffer + 2usize.pow((i%self.pplevel) as u32);
                }
                if i == 255 && buffer != 0{
                    out.g.add_assign(&self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel) + (buffer-1)]);
                    buffer = 0;
                }
            }
            if buffer != 0{
                 panic!("I KNEW IT");
            }
        }
        Ok(())
    }*/
    
    fn preprocess(&mut self, level: usize) -> PyResult<()> {
        self.pplevel = level;
        //Everything requires a different kind of int (and only works with that kind)
        let mut base: u64 = 2;
        //calling pow on a u64 only accepts a u32 parameter for reasons undocumented
        base = base.pow(level as u32);
        let ppsize = (base - 1) * ((252 + level as u64 - 1)/(level as u64));
        self.pp = Vec::with_capacity(ppsize as usize);
        let factor = Scalar::from(base);
        self.pp.push(self.g.0.to_affine_niels());
        for i in 1..base-1
        {
            //Yes, I really need to expicitly cast the indexing variable...
            //let mut next = self.pp[i as usize -1].clone();
            let next = &self.g.0 + &self.pp[i as usize -1];
            //next.add_assign(&self.g);
            self.pp.push(next.to_extended().to_affine_niels());
        }
        //(x + y - 1) / y is a way to round up the integer division x/y
        for i in base-1..(base - 1) * ((252 + level as u64 - 1)/(level as u64)) {
            //let mut next = self.pp[i as usize - (base-1) as usize].clone();
            //Wait, so add_assign takes a borrowed object but mul_assign doesn't?!?!?!?
            let temp = &EdwardsPoint::identity() + &self.pp[i as usize - (base-1) as usize];
            let mut next = temp.to_extended();
            next.mul_assign(factor);
            self.pp.push(next.to_affine_niels());
        }
        //It's not really Ok. This is terrible.
        Ok(())
    }
 
    fn ppmul(&self, prodend: &PyRistScalar, out: &mut PyRistG) -> PyResult<()>
    {
        if self.pp.len() == 0
        {
            out.g = self.g.clone();
            out.g.mul_assign(prodend.scalar);
        }
        else
        {
            let zero = Scalar::zero();
            out.g.mul_assign(zero);
            let mut scalarbytes = prodend.scalar.to_bytes();
            scalarbytes.reverse();
            let hexstr = hex::encode(scalarbytes);
            let binstr = hex_to_bin(&hexstr);
            let mut buffer = 0usize;
            for (i, c) in binstr.chars().rev().enumerate()
            {
                if i%self.pplevel == 0 && buffer != 0
                {
                    //(2**level - 1)*(i/level - 1) + (buffer - 1)
                    let temp = &out.g.0 + &self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)];
                    out.g.0 = temp.to_extended();
                    //out.g.0 = &out.g.0 + &self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)];
                    buffer = 0;
                }
                if c == '1'
                {
                    buffer = buffer + 2usize.pow((i%self.pplevel) as u32);
                }
                if i == 255 && buffer != 0{
                    let temp = &out.g.0 + &self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)];
                    //out.g.0 = &out.g.0 + &self.pp[(2usize.pow(self.pplevel as u32) - 1)*(i/self.pplevel - 1) + (buffer-1)];
                    out.g.0 = temp.to_extended();
                    buffer = 0;
                }
            }
            if buffer != 0{
                 panic!("I KNEW IT");
            }
        }
        Ok(())
    }
    
    fn get_pplevel(&self) -> PyResult<usize> {
        Ok(self.pplevel)
    }

    /*fn pow(&self, rhs: PyRistScalar)  -> PyResult<PyRistG> {
        let mut out = PyRistG{
            g: RistrettoPoint::identity(),
            pp: Vec::new(),
            pplevel : 0
        };
        self.ppmul(&rhs, &mut out).unwrap();
        Ok(out)
    }*/
    
    fn pow(&self, rhs: &PyAny)  -> PyResult<PyRistG> {
        let mut out = PyRistG{
            g: RistrettoPoint::identity(),
            pp: Vec::new(),
            pplevel : 0
        };
        let exp = pyscalar_from_pyany(&rhs)?;
        self.ppmul(&exp, &mut out).unwrap();
        Ok(out)
    }
    
    //todo: they have their own from hash function
    #[staticmethod]
    fn hash(bytestr: &PyBytes) -> PyResult<PyRistG>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let g = RistrettoPoint::random(&mut rng);
        Ok(PyRistG{
            g: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn hash_many(bytestr: &PyBytes, length: usize) -> PyResult<Vec<PyRistG>>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = Vec::with_capacity(length);
        for i in 0..length{
            let g = RistrettoPoint::random(&mut rng);
            out.push(PyRistG{
                g: g,
                pp: Vec::new(),
                pplevel : 0
            });
        }
        Ok(out)
    }
    
    #[staticmethod]
    fn identity() -> PyResult<PyRistG> {
        let g =  RistrettoPoint::identity();
        Ok(PyRistG{
            g: g,
            pp: Vec::new(),
            pplevel : 0
        })
    }
    
    #[staticmethod]
    fn rand(a: Option<Vec<u32>>) -> PyResult<PyRistG> {
        match a {
            None => {
                let mut rng = ChaCha20Rng::from_entropy();
                let g = RistrettoPoint::random(&mut rng);
                Ok(PyRistG{
                    g: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            },
            Some(a) => {
                let mut seed: [u32;8] = [0,0,0,0,0,0,0,0];
                let mut i = 0;
                for item in a.iter(){
                    let myu32: &u32 = item;
                    seed[i] = *myu32;
                    i = i + 1;
                }
                let mut rng = ChaCha20Rng::from_seed(swap_seed_format(seed));
                let g = RistrettoPoint::random(&mut rng);
                Ok(PyRistG{
                    g: g,
                    pp: Vec::new(),
                    pplevel : 0
                })
            }
        }
        
    }
}

#[pyproto]
impl PyNumberProtocol for PyRistG {
    fn __mul__(lhs: PyRistG, rhs: PyRistG) -> PyResult<PyRistG> {
        let mut out = PyRistG{
            g: RistrettoPoint::identity(),
            pp: Vec::new(),
            pplevel : 0
        };
        out.g.clone_from(&lhs.g);
        out.g.add_assign(&rhs.g);
        Ok(out)
    }
    fn __imul__(&mut self, other: PyRistG) -> PyResult<()> {
        self.add_assign(&other)?;
        Ok(())
    }
    fn __truediv__(lhs: PyRistG, rhs: PyRistG) -> PyResult<PyRistG> {
        let mut out = PyRistG{
            g: RistrettoPoint::identity(),
            pp: Vec::new(),
            pplevel : 0
        };
        out.g.clone_from(&lhs.g);
        out.g.add_assign(&rhs.g.neg());
        Ok(out)
    }
    // Somehow this is faster AND more general? Hell yeah!
    fn __pow__(lhs: PyRistG, rhs: &PyAny, _mod: Option<&'p PyAny>)  -> PyResult<PyRistG> {
        let mut out = PyRistG{
            g: RistrettoPoint::identity(),
            pp: Vec::new(),
            pplevel : 0
        };
        let exp = pyscalar_from_pyany(&rhs)?;
        lhs.ppmul(&exp, &mut out).unwrap();
        Ok(out)
        /*let rhscel = &rhs.downcast::<PyCell<PyRistScalar>>();
        if rhscel.is_err(){
            let exp: BigInt = rhs.extract()?;
            //todo: account for sign
            let s: Scalar = Scalar::from_bytes_mod_order(exp.to_bytes_le().1.try_into().unwrap());
            lhs.ppmul(&PyRistScalar{scalar: s}, &mut out).unwrap();
        }
        else {
            //let rhscel2 = rhscel.as_ref().unwrap();
            let exp: &PyRistScalar = &rhscel.as_ref().unwrap().borrow();
            lhs.ppmul(&exp, &mut out).unwrap();
        }
        Ok(out)*/
    }
    /*fn __pow__(lhs: PyG1, rhs: PyFr, _mod: Option<&'p PyAny>)  -> PyResult<PyG1> {
        let mut out = PyG1{
            g1: G1::one(),
            pp: Vec::new(),
            pplevel : 0
        };
        lhs.ppmul(&rhs, &mut out).unwrap();
        Ok(out)
    }*/
}
#[pyproto]
impl PyObjectProtocol for PyRistG {
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyRistG ,b: &PyAny| {
            let othercel = &b.downcast::<PyCell<PyRistG>>();
            if othercel.is_err(){
                false
            }
            else{
                let otherg: &PyRistG = &othercel.as_ref().unwrap().borrow();
                a.g == otherg.g
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
    fn __str__(&self) -> PyResult<String> {
        let compressed = self.g.compress();
        Ok(format!("(s: {})",hex::encode(compressed.to_bytes())))
    }
    fn __repr__(&self) -> PyResult<String> {
        let compressed = self.g.compress();
        Ok(format!("(s: {})",hex::encode(compressed.to_bytes())))
    }
}

#[pyclass(module = "pypairing", name = Curve25519ZR)]
#[derive(Clone)]
struct PyRistScalar {
   scalar : Scalar
}

#[pymethods]
impl PyRistScalar {

    #[new]
    fn new(s1: Option<&PyAny>) -> Self {
        match s1 {
            None => PyRistScalar{scalar:Scalar::one()},
            Some(s1) => {
                pyscalar_from_pyany(&s1).unwrap()
            }
        }
    }

    fn negate(&mut self) -> PyResult<()> {
        self.scalar = self.scalar.neg();
        Ok(())
    }

    fn inverse(&mut self) -> PyResult<()> {
        self.scalar = self.scalar.invert();
        Ok(())
    }


    fn add_assign(&mut self, other: &PyRistScalar) -> PyResult<()> {
        self.scalar.add_assign(&other.scalar);
        Ok(())
    }

    fn sub_assign(&mut self, other: &PyRistScalar) -> PyResult<()> {
        self.scalar.sub_assign(&other.scalar);
        Ok(())
    }

    fn mul_assign(&mut self, other: &PyRistScalar) -> PyResult<()> {
        self.scalar.mul_assign(&other.scalar);
        Ok(())
    }
    
    fn pow_assign(&mut self, other: &PyAny) -> PyResult<()> {
        let base = BigInt::from_bytes_le(Sign::Plus, &self.scalar.to_bytes());
        let curve25519_r = BigInt::from_bytes_le(Sign::Plus, &vec![
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]);
        let curve25519_r_minus_1 = BigInt::from_bytes_le(Sign::Plus, &vec![
        0xec, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ]);
        let mut exp: BigInt = other.extract()?;
        exp = exp.mod_floor(&curve25519_r_minus_1);
        let result = base.modpow(&exp, &curve25519_r);
        let pyscalar = bigint_to_pyscalar(&result);
        self.scalar = pyscalar.scalar;
        Ok(())
    }
    
    fn to_montgomery(&self) -> PyResult<PyRistScalar> {
        let mut out = PyRistScalar{scalar: Scalar::one()};
        out.scalar.clone_from(&self.scalar);
        out.scalar = out.scalar.to_montgomery();
        Ok(out)
    }
    
    fn from_montgomery(&self) -> PyResult<PyRistScalar> {
        let mut out = PyRistScalar{scalar: Scalar::one()};
        out.scalar.clone_from(&self.scalar);
        out.scalar = out.scalar.from_montgomery();
        Ok(out)
    }

    fn is_zero(&self) -> bool {
        self.scalar == Scalar::zero()
    }

    fn equals(&self, other: &PyRistScalar) -> bool {
        self.scalar == other.scalar
    }

    /// Copy other into self
    fn copy(&mut self, other: &PyRistScalar) -> PyResult<()> {
        self.scalar = other.scalar;
        Ok(())
    }
    
    pub fn __getstate__<'p>(&self, py: Python<'p>) -> PyResult<&'p PyBytes> {
        Ok(PyBytes::new(py, &self.scalar.to_bytes()))
    }
    
    pub fn __setstate__(&mut self, list: &PyAny) -> PyResult<()>
    {
        let arr: [u8; 32] = list.extract()?;
        let myscalar = Scalar::from_bytes_mod_order(arr);
        self.scalar = myscalar;
        Ok(())
    }
    
    #[staticmethod]
    fn hash(bytestr: &PyBytes) -> PyResult<PyRistScalar>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let s = Scalar::random(&mut rng);
        Ok(PyRistScalar{scalar: s})
    }
    
    #[staticmethod]
    fn hash_many(bytestr: &PyBytes, length: usize) -> PyResult<Vec<PyRistScalar>>{
        let bytes: &[u8] = bytestr.as_bytes();
        let mut hasher = Sha256::new();
        hasher.input(bytes);
        let result = hasher.result();
        let seed: [u8; 32] = result.as_slice().try_into().unwrap();
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut out = Vec::with_capacity(length);
        for i in 0..length{
            let s = Scalar::random(&mut rng);
            out.push(PyRistScalar{scalar: s});
        }
        Ok(out)
    }
    
    #[staticmethod]
    fn rand() -> PyResult<PyRistScalar> {
            let mut rng = ChaCha20Rng::from_entropy();
            let s = Scalar::random(&mut rng);
            Ok(PyRistScalar{scalar: s})
    }
    
    #[staticmethod]
    fn random() -> PyResult<PyRistScalar> {
        Ok(PyRistScalar::rand()?)
    }

}

#[pyproto]
impl PyNumberProtocol for PyRistScalar {
    
    fn __add__(lhs: PyRistScalar, rhs: &PyAny) -> PyResult<PyRistScalar> {
        let mut out: PyRistScalar = pyscalar_from_pyany(&rhs)?;
        out.add_assign(&lhs);
        Ok(out)
    }
    
    fn __truediv__(lhs: PyRistScalar, rhs: &PyAny) -> PyResult<PyRistScalar> {
        let mut out: PyRistScalar = pyscalar_from_pyany(&rhs)?;
        out.inverse();
        out.mul_assign(&lhs);
        Ok(out)
    }
    
    fn __mul__(lhs: PyRistScalar, rhs: &PyAny) -> PyResult<PyRistScalar> {
        let mut out: PyRistScalar = pyscalar_from_pyany(&rhs)?;
        //out.scalar = out.scalar.to_montgomery();
        //let lhs_mont = PyRistScalar{scalar: lhs.scalar.to_montgomery()};
        //out.mul_assign(&lhs_mont);
        //out.scalar = out.scalar.from_montgomery();
        out.mul_assign(&lhs);
        //out.scalar = out.scalar.from_montgomery();
        Ok(out)
    }
    
    fn __neg__(&self) -> PyResult<PyRistScalar> {
        let mut out = PyRistScalar{
            scalar: self.scalar.neg()
        };
        Ok(out)
    }
    
    fn __int__(&self) -> PyResult<BigInt> {
        let bi = BigInt::from_bytes_le(Sign::Plus, &self.scalar.to_bytes());
        Ok(bi)
    }
    
    fn __pow__(lhs: PyRistScalar, rhs: &PyAny, _mod: Option<&'p PyAny>) -> PyResult<PyRistScalar> {
        let mut out = PyRistScalar{
            scalar: Scalar::one()
        };
        out.scalar.clone_from(&lhs.scalar);
        out.pow_assign(&rhs);
        Ok(out)
    }
    
    fn __sub__(lhs: PyRistScalar, rhs: &PyAny) -> PyResult<PyRistScalar> {
        let mut out = PyRistScalar{scalar: lhs.scalar.clone()};
        let subend = pyscalar_from_pyany(&rhs)?;
        out.sub_assign(&subend);
        Ok(out)
    }
}

#[pyproto]
impl PyObjectProtocol for PyRistScalar {
    fn __richcmp__(&self, other: &PyAny, op: CompareOp) -> PyResult<bool> {
        let eq = |a:&PyRistScalar ,b: &PyAny| {
            let otherscalar = pyscalar_from_pyany(&b);
            if otherscalar.is_err(){
                false
            }
            else{
                a.scalar == otherscalar.unwrap().scalar
            }
        };
        match op {
            CompareOp::Eq => Ok(eq(self, other)),
            CompareOp::Ne => Ok(!eq(self, other)),
            CompareOp::Lt => Ok(false),
            CompareOp::Le => Ok(false),
            CompareOp::Gt => Ok(false),
            CompareOp::Ge => Ok(false),
        }
    }
    fn __str__(&self) -> PyResult<String> {
        let mut scalarbytes = self.scalar.to_bytes();
        scalarbytes.reverse();
        Ok(format!("{}", hex::encode(scalarbytes)))
    }
    fn __repr__(&self) -> PyResult<String> {
        let mut scalarbytes = self.scalar.to_bytes();
        scalarbytes.reverse();
        Ok(format!("{}", hex::encode(scalarbytes)))
    }
}


#[pyfunction]
fn vec_sum(a: &PyList, py: Python) -> PyResult<String>{
    let mut sum =  Fr::from_str("0").unwrap();
    for item in a.iter(){
        //let myobj  = item.to_object(py);
        //let myobj2 = myobj.as_ref(py).extract::<Py<PyFr>>();
        //let myfr: &PyFr = myobj2.as_ref(py).unwrap();
        //let myfr: &PyFr = item.try_into().unwrap();
        //let myfr: &PyFr = item.downcast()?;
        //let myfr = PyFr::extract(item)?;
        //let myfr = &PyFr::try_from(item)?;
        //let myfr = item.cast_as::<PyFr>()?;
        let itemcel: &PyCell<PyFr> = item.downcast()?;
        let myfr: &PyFr = &itemcel.borrow();
        sum.add_assign(&myfr.fr);
    }
    Ok(format!("{}",sum))
}

#[pyfunction]
fn hashfrs(a: &PyList) -> PyResult<String>{
    let mut string =  String::from("");
    for item in a.iter(){
        //let myfr = item.into::<PyFr>().unwrap();
        let itemcel: &PyCell<PyFr> = item.downcast()?;
        let myfr: &PyFr = &itemcel.borrow();
        string.push_str(&myfr.__str__().unwrap())
    }
    let bytes = string.into_bytes();
    let mut hasher = Sha256::new();
    hasher.input(bytes);
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}

#[pyfunction]
fn hashcurve25519zrs(a: &PyList) -> PyResult<String>{
    let mut string =  String::from("");
    for item in a.iter(){
        let itemcel: &PyCell<PyRistScalar> = item.downcast()?;
        let myfr: &PyRistScalar = &itemcel.borrow();
        string.push_str(&myfr.__str__().unwrap())
    }
    let bytes = string.into_bytes();
    let mut hasher = Sha256::new();
    hasher.input(bytes);
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}



/*#[pyfunction]
fn hashg1s(a: &PyList) -> PyResult<String>{
    //let mut string =  String::from("");
    let mut vec = Vec::new();
    let mut hasher = Sha256::new();
    for item in a.iter(){
        //let myg1: &PyG1 = item.try_into().unwrap();
        let itemcel: &PyCell<PyG1> = item.downcast()?;
        let myg1: &PyG1 = &itemcel.borrow();
        let fqrx = FqRepr::from(myg1.g1.into_affine().x);
        let arr = fqrx.as_ref();
        vec.extend_from_slice(&arr);
        //let arr: [u64; 32] = &myg1.g1.x.try_into().unwrap();
    }
    for num in &vec {
        hasher.input(num.to_be_bytes());
    }
    //hasher.input(bytes);
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}*/

//TODO: Optimizing: 1)See if Serde can give you the byte structure you want 2) call batch_normalization
#[pyfunction]
fn hashg1s(mut a: Vec<PyG1>) -> PyResult<String>{
    let mut hasher = Sha256::new();
    for point in a {
        let fqrx = FqRepr::from(point.g1.into_affine().x);
        let arr = fqrx.as_ref();
        for num in arr {
            hasher.input(num.to_be_bytes());
        }
    }
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}

#[pyfunction]
fn hashg1sbn(mut a: Vec<PyG1>) -> PyResult<String>{
    let mut hasher = Sha256::new();
    pyg1_batch_normalization(&mut a);
    for point in &a {
        let fqrx = FqRepr::from(point.g1.into_affine().x);
        let arr = fqrx.as_ref();
        for num in arr {
            hasher.input(num.to_be_bytes());
        }
    }
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}

#[pyfunction]
fn hashcurve25519gs(mut a: Vec<PyRistG>) -> PyResult<String>{
    let mut hasher = Sha256::new();
    for point in a {
        hasher.input(point.g.compress().to_bytes());
    }
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}

#[pyfunction]
fn hashcurve25519gsbn(mut a: Vec<PyRistG>) -> PyResult<String>{
    let mut hasher = Sha256::new();
    let mut uncompressed = Vec::with_capacity(a.len());
    for g in a.iter(){
        uncompressed.push(g.g);
    }
    //this doubles as a part of compressing for cost reasons, but that doesn't matter here 
    //(as long as we're consistent about it)
    let compressed = RistrettoPoint::double_and_compress_batch(&uncompressed);
    for point in compressed {
        hasher.input(point.to_bytes());
    }
    let result = hasher.result();
    let text = hex::encode(&result[..]);
    Ok(format!("{}",text))
}

fn pyg1_batch_normalization(v: &mut [PyG1]) {
                // Montgomery’s Trick and Fast Implementation of Masked AES
                // Genelle, Prouff and Quisquater
                // Section 3.2

                // First pass: compute [a, ab, abc, ...]
                let mut prod = Vec::with_capacity(v.len());
                let mut tmp = Fq::one();
                for g in v
                    .iter_mut()
                    // Ignore normalized elements
                    .filter(|g| !g.g1.is_normalized())
                {
                    tmp.mul_assign(&g.g1.z);
                    prod.push(tmp);
                }

                // Invert `tmp`.
                tmp = tmp.inverse().unwrap(); // Guaranteed to be nonzero.

                // Second pass: iterate backwards to compute inverses
                for (g, s) in v
                    .iter_mut()
                    // Backwards
                    .rev()
                    // Ignore normalized elements
                    .filter(|g| !g.g1.is_normalized())
                    // Backwards, skip last element, fill in one for last term.
                    .zip(
                        prod.into_iter()
                            .rev()
                            .skip(1)
                            .chain(Some(Fq::one())),
                    )
                {
                    // tmp := tmp * g.z; g.z := tmp * s = 1/z
                    let mut newtmp = tmp;
                    newtmp.mul_assign(&g.g1.z);
                    g.g1.z = tmp;
                    g.g1.z.mul_assign(&s);
                    tmp = newtmp;
                }

                // Perform affine transformations
                for g in v.iter_mut().filter(|g| !g.g1.is_normalized()) {
                    let mut z = g.g1.z; // 1/z
                    z.square(); // 1/z^2
                    g.g1.x.mul_assign(&z); // x/z^2
                    z.mul_assign(&g.g1.z); // 1/z^3
                    g.g1.y.mul_assign(&z); // y/z^3
                    g.g1.z = Fq::one(); // z = 1
                }
}


#[pyfunction]
fn dotprod(a: &PyList, b: &PyList) -> PyResult<PyFr>{
    let mut output = PyFr{ fr: Fr::zero()};
    let mut temp = Fr::zero();
    for (ai, bi) in a.iter().zip(b){
        //let aif: &PyFr = ai.try_into().unwrap();
        //let bif: &PyFr = bi.try_into().unwrap();
        let aicel: &PyCell<PyFr> = ai.downcast()?;
        let aif: &PyFr = &aicel.borrow();
        let bicel: &PyCell<PyFr> = bi.downcast()?;
        let bif: &PyFr = &bicel.borrow();
        temp.clone_from(&aif.fr);
        temp.mul_assign(&bif.fr);
        output.fr.add_assign(&temp);
    }
    Ok(output)
}

#[pyfunction]
fn curve25519dotprod(a: &PyList, b: &PyList) -> PyResult<PyRistScalar>{
    let mut output = PyRistScalar{ scalar: Scalar::zero()};
    let mut temp = Scalar::zero();
    for (ai, bi) in a.iter().zip(b){
        //let aif: &PyFr = ai.try_into().unwrap();
        //let bif: &PyFr = bi.try_into().unwrap();
        let aicel: &PyCell<PyRistScalar> = ai.downcast()?;
        let aif: &PyRistScalar = &aicel.borrow();
        let bicel: &PyCell<PyRistScalar> = bi.downcast()?;
        let bif: &PyRistScalar = &bicel.borrow();
        temp.clone_from(&aif.scalar);
        temp.mul_assign(&bif.scalar);
        output.scalar.add_assign(&temp);
    }
    Ok(output)
}

#[pyfunction]
fn blsmultiexp(gs: &PyList, zrs: &PyList) -> PyResult<PyG1>{
    let mut output = PyG1{ g1: G1::zero(), pp: Vec::new(), pplevel:0 };
    let mut temp = Scalar::zero();
    for (ai, bi) in gs.iter().zip(zrs){
        //let aif: &PyFr = ai.try_into().unwrap();
        //let bif: &PyFr = bi.try_into().unwrap();
        let aicel: &PyCell<PyG1> = ai.downcast()?;
        let aif: &PyG1 = &aicel.borrow();
        let temp = aif.pow(bi)?;
        output.add_assign(&temp);
    }
    Ok(output)
}

#[pyfunction]
fn curve25519multiexp(gs: &PyList, zrs: &PyList) -> PyResult<PyRistG>{
    let mut scalars: Vec<Scalar> = Vec::new();
    let mut points: Vec<RistrettoPoint> = Vec::new();
    for (ai, bi) in gs.iter().zip(zrs){
        //let aif: &PyFr = ai.try_into().unwrap();
        //let bif: &PyFr = bi.try_into().unwrap();
        let aicel: &PyCell<PyRistG> = ai.downcast()?;
        let aif: &PyRistG = &aicel.borrow();
        points.push(aif.g);
        let bicel: &PyCell<PyRistScalar> = bi.downcast()?;
        let bif: &PyRistScalar = &bicel.borrow();
        scalars.push(bif.scalar);
    }
    Ok(PyRistG{
        g: RistrettoPoint::vartime_multiscalar_mul(scalars, points), 
        pp: Vec::new(),
        pplevel : 0
    })
}

#[pyfunction]
fn condense_list<'p>(inlist: &PyList, x: &PyFr, py: Python<'p>) -> PyResult<&'p PyList> {
    //let l: &PyList = PyList::empty(py);
    //let weed = PyFr{
    //    fr: Fr::one(),
    //};
    let mut items: Vec<&PyCell<PyFr>> = Vec::new();
    for item in inlist.iter(){
        let aicel: &PyCell<PyFr> = item.downcast()?;
        let aif: &PyFr = &aicel.borrow();
        let mut weed = PyFr{
            fr: Fr::one(),
        };
        weed.fr.clone_from(&aif.fr);
        items.push(PyCell::new(py, weed).unwrap());
        //l.append::<PyFr>(aif.into_py(py));
        //inlist.set_item(1, aif);
    }
    //l.append(weed.into_py(py));
    Ok(PyList::new(py, items))
}

#[pyfunction]
//fn pair<'p>(py: Python<'p>, a: &PyG1, b: &PyG2) -> PyResult<&'p PyFq12> {
fn pair(a: &PyG1, b: &PyG2) -> PyResult<PyFq12> {
    let affa = a.g1.into_affine();
    let myfq12 = affa.pairing_with(&b.g2.into_affine());
    Ok(PyFq12{  fq12: myfq12,
                pp: Vec::new(),
                pplevel : 0
    })
}

#[derive(Clone)]
enum preprocessable{
    PyG1,
    PyG2,
    PyFq12
}

/*#[pyclass(module = "pypairing")]
#[derive(Clone)]
struct Point {
}

#[pymethods]
impl Point {
    #[new]
    fn new() -> Self {
        Point{}
    }
}

#[pyfunction]
fn precomp_list(mut list: Vec<preprocessable>, level: usize) -> PyResult<()> {
//fn precomp_list(list: &mut Vec, level: usize) -> PyResult<()> {
    for i in 1..2 {
    //for item in list.iter(){
       //item.preprocess(level);
       let i = 2;
    }
    Ok(())
}*/

fn bigint_to_pyfr(bint: &BigInt) -> PyFr {
    let bls12_381_r = BigInt::new(Sign::Plus, vec![1u32,4294967295u32,4294859774u32,1404937218u32,161601541u32,859428872u32,698187080u32,1944954707u32]);
    let mut uint = bint % &bls12_381_r;
    // The % in rust is not modulo, it's remainder!
    if uint < BigInt::from(0u8) {
        uint += &bls12_381_r;
    }
    //BigInts only serialize/deserialize into Vec<u32>, while Fr only works with Vec<u64>
    //They are not cross compatible ヽ(ಠ_ಠ)ノ
    let s1 = &uint % 2u128.pow(64);
    let s2 = (&uint >> 64) % 2u128.pow(64);
    let s3: BigInt = (&uint >> 128) % 2u128.pow(64);
    let s4: BigInt = &uint >> 192;
    let myfr = Fr::from_repr(FrRepr([s1.to_u64().unwrap(),s2.to_u64().unwrap(),s3.to_u64().unwrap(),s4.to_u64().unwrap()])).unwrap();
    let mypyfr = PyFr{
        fr: myfr
    };
    mypyfr
}

fn bigint_to_pyfrexp(bint: &BigInt) -> PyFr {
    let bls12_381_r = BigInt::new(Sign::Plus, vec![0u32,4294967295u32,4294859774u32,1404937218u32,161601541u32,859428872u32,698187080u32,1944954707u32]);
    let mut uint = bint % &bls12_381_r;
    // The % in rust is not modulo, it's remainder!
    if uint < BigInt::from(0u8) {
        uint += &bls12_381_r;
    }
    //BigInts only serialize/deserialize into Vec<u32>, while Fr only works with Vec<u64>
    //They are not cross compatible ヽ(ಠ_ಠ)ノ
    let s1 = &uint % 2u128.pow(64);
    let s2 = (&uint >> 64) % 2u128.pow(64);
    let s3: BigInt = (&uint >> 128) % 2u128.pow(64);
    let s4: BigInt = &uint >> 192;
    let myfr = Fr::from_repr(FrRepr([s1.to_u64().unwrap(),s2.to_u64().unwrap(),s3.to_u64().unwrap(),s4.to_u64().unwrap()])).unwrap();
    let mypyfr = PyFr{
        fr: myfr
    };
    mypyfr
}

fn bigint_to_pyscalar(bint: &BigInt) -> PyRistScalar {
    let curve25519_r = BigInt::from_bytes_le(Sign::Plus, &vec![
        0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
        0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
    ]);
    let mut modr = bint.clone();
    modr = modr.mod_floor(&curve25519_r);
    let mut modr_bytes = modr.to_bytes_le().1;
    let padding_len = 32 - modr_bytes.len();
    let mut padding: Vec<u8> = vec![0;padding_len];
    //padding.append(&mut modr_bytes);
    modr_bytes.append(&mut padding);
    let myscalar = Scalar::from_bytes_mod_order(modr_bytes.try_into().unwrap_or_else(|_| panic!("F's in the chat, boys")));
    let mypyscalar = PyRistScalar{
        scalar: myscalar
    };
    mypyscalar
}

fn swap_seed_format(inarr: [u32;8]) -> [u8;32] {
    let mut out: [u8;32] = [0; 32];
    for i in 0..8 {
        let next_four = inarr[i].to_be_bytes();
        out[4*i] = next_four[0];
        out[4*i+1] = next_four[1];
        out[4*i+2] = next_four[2];
        out[4*i+3] = next_four[3];
    }
    out
}

fn pyfr_from_pyany(any: &PyAny) -> PyResult<PyFr> {
    let mut out = PyFr{
        fr: Fr::one()
    };
    let anycel = &any.downcast::<PyCell<PyFr>>();
    if anycel.is_err(){
        let bi: BigInt = any.extract()?;
        let mypyfr = bigint_to_pyfr(&bi);
        out.fr = mypyfr.fr;
    }
    else{
        let mypyfr: &PyFr = &anycel.as_ref().unwrap().borrow();
        out.fr.clone_from(&mypyfr.fr);
    }
    Ok(out)
}

fn pyfr_from_pyanyexp(any: &PyAny) -> PyResult<PyFr> {
    let mut out = PyFr{
        fr: Fr::one()
    };
    let anycel = &any.downcast::<PyCell<PyFr>>();
    if anycel.is_err(){
        let bi: BigInt = any.extract()?;
        let mypyfr = bigint_to_pyfrexp(&bi);
        out.fr = mypyfr.fr;
    }
    else{
        let mypyfr: &PyFr = &anycel.as_ref().unwrap().borrow();
        out.fr.clone_from(&mypyfr.fr);
    }
    Ok(out)
}

fn pyscalar_from_pyany(any: &PyAny) -> PyResult<PyRistScalar> {
    let mut out = PyRistScalar{
        scalar: Scalar::one()
    };
    let anycel = &any.downcast::<PyCell<PyRistScalar>>();
    if anycel.is_err(){
        let bi: BigInt = any.extract()?;
        let mypyfr = bigint_to_pyscalar(&bi);
        out.scalar = mypyfr.scalar;
    }
    else{
        let mypyscalar: &PyRistScalar = &anycel.as_ref().unwrap().borrow();
        out.scalar.clone_from(&mypyscalar.scalar);
    }
    Ok(out)
}

#[pymodule]
fn pypairing(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<PyG1>()?;
    m.add_class::<PyG2>()?;
    m.add_class::<PyFq>()?;
    m.add_class::<PyFqRepr>()?;
    m.add_class::<PyFq2>()?;
    m.add_class::<PyFq6>()?;
    m.add_class::<PyFq12>()?;
    m.add_class::<PyFr>()?;
    m.add_class::<PyRistG>()?;
    m.add_class::<PyRistScalar>()?;
    //m.add_function(wrap_pyfunction!(vec_sum))?;
    m.add_wrapped(wrap_pyfunction!(pair))?;
    m.add_wrapped(wrap_pyfunction!(vec_sum))?;
    m.add_wrapped(wrap_pyfunction!(hashfrs))?;
    m.add_wrapped(wrap_pyfunction!(hashg1s))?;
    m.add_wrapped(wrap_pyfunction!(hashg1sbn))?;
    m.add_wrapped(wrap_pyfunction!(dotprod))?;
    m.add_wrapped(wrap_pyfunction!(condense_list))?;
    m.add_wrapped(wrap_pyfunction!(blsmultiexp))?;

    m.add_wrapped(wrap_pyfunction!(hashcurve25519zrs))?;
    m.add_wrapped(wrap_pyfunction!(hashcurve25519gs))?;
    m.add_wrapped(wrap_pyfunction!(hashcurve25519gsbn))?;
    m.add_wrapped(wrap_pyfunction!(curve25519dotprod))?;
    m.add_wrapped(wrap_pyfunction!(curve25519multiexp))?;
    Ok(())
}


/// An error that may occur when trying to decode an `EncodedPoint`.
#[derive(Debug)]
pub enum GroupDecodingError {
    /// The coordinate(s) do not lie on the curve.
    NotOnCurve,
    /// The element is not part of the r-order subgroup.
    NotInSubgroup,
    /// One of the coordinates could not be decoded
    CoordinateDecodingError(&'static str, PrimeFieldDecodingError),
        //assert!(a.pairing_with(&b) == pairing(a, b));

    /// The compression mode of the encoded element was not as expected
    UnexpectedCompressionMode,
    /// The encoding contained bits that should not have been set
    UnexpectedInformation,
}

impl Error for GroupDecodingError {
    fn description(&self) -> &str {
        match *self {
            GroupDecodingError::NotOnCurve => "coordinate(s) do not lie on the curve",
            GroupDecodingError::NotInSubgroup => "the element is not part of an r-order subgroup",
            GroupDecodingError::CoordinateDecodingError(..) => "coordinate(s) could not be decoded",
            GroupDecodingError::UnexpectedCompressionMode => {
                "encoding has unexpected compression mode"
            }
            GroupDecodingError::UnexpectedInformation => "encoding has unexpected information",
        }
    }
}

impl fmt::Display for GroupDecodingError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            GroupDecodingError::CoordinateDecodingError(description, ref err) => {
                write!(f, "{} decoding error: {}", description, err)
            }
            _ => write!(f, "{}", self.description()),
        }
    }
}

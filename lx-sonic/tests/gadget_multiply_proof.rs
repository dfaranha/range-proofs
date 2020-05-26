
use pairing::{Engine, Field, PrimeField};
use pairing::bls12_381::{Bls12, Fr};
use bellman::{Circuit, ConstraintSystem, SynthesisError};
// use sonic::cs::{Circuit, ConstraintSystem};
use rand::{thread_rng, Rng};
// For benchmarking
use std::time::{Instant};
use lx_sonic::srs::SRS;

use lx_sonic::cs::Basic;
use lx_sonic::helped::adaptor::AdaptorCircuit;
use lx_sonic::helped::{Proof, MultiVerifier};
use lx_sonic::polynomials::Polynomial;

pub fn multiply<E: Engine>(
    a: E::Fr,
    b: E::Fr,
) -> E::Fr
{
	let mut tmp = b;
    tmp.mul_assign(&a);

    tmp
}

#[derive(Clone)]
pub struct MultiplyDemo<E: Engine> {
    a: Option<E::Fr>,
    b: Option<E::Fr>,
	c: Option<E::Fr>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MultiplyDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let a = cs.alloc(|| "a", || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let b = cs.alloc(|| "b", || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let c = cs.alloc_input(|| "c", || {
            self.c.ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce(
            || "tmp = xL * xR",
            |lc| lc + a,
            |lc| lc + b,
            |lc| lc + c
        );

        Ok(())
    }
}

/// This is our demo circuit for proving knowledge of the
/// preimage of a Multiply hash invocation.
#[derive(Clone)]
struct MultiplyDemoNoInputs<E: Engine> {
    a: Option<E::Fr>,
    b: Option<E::Fr>,
    c: Option<E::Fr>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for MultiplyDemoNoInputs<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError>
    {
        let a = cs.alloc(|| "a", || {
            self.a.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let b = cs.alloc(|| "b", || {
            self.b.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // tmp = (xL + Ci)^2
        let c_value = self.a.map(|mut e| {
            e.mul_assign(&self.b.unwrap());
            e
        });
        let c = cs.alloc(|| "c", || {
            c_value.ok_or(SynthesisError::AssignmentMissing)
        })?;

        cs.enforce(
            || "tmp = (xL * xR)",
            |lc| lc + a,
            |lc| lc + b,
            |lc| lc + c
        );

        Ok(())
    }
}

#[test]
fn test_multiply_gadget_sonic_wo_inputs() {
    let srs_x = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();

    // let start = Instant::now();
    let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);
    // println!("Done in {:?}", start.elapsed());

    {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

        let a = rng.gen();
        let b = rng.gen();
        let c = multiply::<Bls12>(a, b);

        // Create an instance of our circuit (with the witness)
        let circuit = MultiplyDemoNoInputs {
            a: Some(a),
            b: Some(b),
            c: Some(c),
        };

        // println!("Creating proof");
        let start = Instant::now();
        let proof = Proof::<Bls12, Polynomial<Bls12>>::create_proof::< _, Basic>(&AdaptorCircuit(circuit.clone()), &srs).unwrap();
        println!("(Proving SONIC) Done in {:?}", start.elapsed());

        let rng = thread_rng();
        let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();
        // println!("Verifying 1 proof without advice");
        let start = Instant::now();
        {
            for _ in 0..1 {
                verifier.add_proof(&proof, &[], |_, _| None);
            }
            assert_eq!(verifier.check_all(), true);
        }
        println!("(Verifying SONIC) Done in {:?}", start.elapsed());
    }
}

#[test]
fn test_multiply_gadget_sonic_w_input() {
    let srs_x = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();

    let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    let a = rng.gen();
    let b = rng.gen();
    let c = multiply::<Bls12>(a, b);

    // Create an instance of our circuit (with the
    // witness)
    let circuit = MultiplyDemo {
        a: Some(a),
        b: Some(b),
		c: Some(c),
    };

    let start = Instant::now();
    let proof = Proof::<Bls12, Polynomial<Bls12>>::create_proof::< _, Basic>(&AdaptorCircuit(circuit.clone()), &srs).unwrap();
    println!("(Proving SONIC input)done in {:?}", start.elapsed());

    let rng = thread_rng();
    let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();

    let start = Instant::now();
    {
        for _ in 0..1 {
            verifier.add_proof(&proof, &[c], |_, _| None);
        }
        assert_eq!(verifier.check_all(), true);
    }
    println!("(Verifying SONIC Input)done in {:?}", start.elapsed());
}

#[test]
fn test_multiply_gadget_groth16() {
    use bellman::groth16::{generate_random_parameters, prepare_verifying_key, create_random_proof, verify_proof};

    // This may not be cryptographically safe, use
    // `OsRng` (for example) in production software.
    let rng = &mut thread_rng();

    // println!("Creating parameters...");

    let params = {
        let circuit = MultiplyDemo::<Bls12> {
            a: None,
            b: None,
			c: None
        };

        generate_random_parameters(circuit, rng).unwrap()
    };

    let pvk = prepare_verifying_key(&params.vk);

    let a = rng.gen();
    let b = rng.gen();
    let c = multiply::<Bls12>(a, b);

	let circuit = MultiplyDemo::<Bls12> {
		a: Some(a),
		b: Some(b),
		c: Some(c),
	};

    // println!("Creating proofs...");
    let start = Instant::now();
    let proof = create_random_proof(circuit, &params, rng).unwrap();
    println!("(Proving Groth16) Done in {:?}", start.elapsed());

    // println!("Verifying proof");
    let start = Instant::now();
    // Check the proof
    assert!(verify_proof(&pvk, &proof, &[c]).unwrap());
    println!("(Verifying Groth16) Done in {:?}", start.elapsed());
}

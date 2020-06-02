#[macro_use]
extern crate criterion;
use criterion::Criterion;
use pairing::{Engine, Field, PrimeField, CurveAffine, CurveProjective};
use pairing::bls12_381::{Bls12, Fr};
use bellman::{Circuit, ConstraintSystem, SynthesisError};

use rand::{thread_rng, Rng};
use std::marker::PhantomData;

use lx_sonic::srs::SRS;
use lx_sonic::cs::Basic;
use lx_sonic::helped::adaptor::AdaptorCircuit;
use lx_sonic::helped::{Proof, MultiVerifier};
use lx_sonic::polynomials::Polynomial;

#[derive(Clone)]
pub struct RangeProofDemo<E: Engine> {
    v: Option<u64>,
	bit_size: usize,
	_marker: PhantomData<E>,
}

/// Our demo circuit implements this `Circuit` trait which
/// is used during paramgen and proving in order to
/// synthesize the constraint system.
impl<'a, E: Engine> Circuit<E> for RangeProofDemo<E> {
    fn synthesize<CS: ConstraintSystem<E>>(
        self,
        cs: &mut CS
    ) -> Result<(), SynthesisError> {
		let v = cs.alloc(|| "v", || {
						if self.v.is_some() {
							let str = self.v.unwrap().to_string();
							Ok(E::Fr::from_str(&str).unwrap())
						} else {
							Err(SynthesisError::AssignmentMissing)
						}
					})?;

		//let mut minus_one = E::Fr::one();
		//minus_one.negate();
		//let mut constraint_v = vec![(v, minus_one)];
		let mut exp_2 = E::Fr::zero();
		for i in 0..self.bit_size {
			let a_value = (self.v.unwrap() >> (self.bit_size - i - 1)) & 1;
			let a = cs.alloc(|| "a", || {
			                if self.v.is_some() {
			                    if a_value == 1 {
			                        Ok(E::Fr::one())
			                    } else {
			                        Ok(E::Fr::zero())
			                    }
			                } else {
			                    Err(SynthesisError::AssignmentMissing)
			                }
			            })?;

			let b_value = 1 - a_value;
			let b = cs.alloc(|| "b", || {
			                if self.v.is_some() {
			                    if b_value == 1 {
			                        Ok(E::Fr::one())
			                    } else {
			                        Ok(E::Fr::zero())
			                    }
			                } else {
			                    Err(SynthesisError::AssignmentMissing)
			                }
			            })?;

			cs.enforce(
	            || "a * b = 0",
	            |lc| lc + a,
	            |lc| lc + b,
	            |lc| lc,
	        );

	        cs.enforce(
	            || "a = 1 - b",
	            |lc| lc + CS::one() - b,
	            |lc| lc + CS::one(),
	            |lc| lc + a,
	        );

			//constraint_v.push((a, exp_2));
			let tmp2 = exp_2;
			exp_2.add_assign(&tmp2);
			if a_value == 1 {
				exp_2.add_assign(&E::Fr::one());
			} else {
				exp_2.add_assign(&E::Fr::zero());
			}
		}

		//println!("{:x?}", constraint_v.iter());

		let sum = cs.alloc(|| "sum", || {
            Ok(exp_2)
        })?;

		cs.enforce(
			|| "v = sum a_i 2^i",
			|lc| lc + v,
			|lc| lc + CS::one(),
			|lc| lc + sum,
		);

        Ok(())
    }
}

fn range_proof_prover(c: &mut Criterion) {
    let srs_x = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();

    let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);

	let min = 0;
	let max = ((1u64 << 16) - 1) as u64;

	c.bench_function("Create range proof", move |b| {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

		let v = rng.gen_range(min, max);
	    let circuit = RangeProofDemo::<Bls12> {
	        v: Some(v),
			bit_size: 16,
	        _marker: PhantomData,
	    };

        b.iter(|| {
            Proof::<Bls12, Polynomial<Bls12>>::create_proof::< _, Basic>(&AdaptorCircuit(circuit.clone()), &srs).unwrap();
        })
    });
}

criterion_group! {
    name = sonic_prove;
    config = Criterion::default().sample_size(10);
    targets =
    range_proof_prover,
}

fn range_proof_verifier(c: &mut Criterion) {
    let srs_x = Fr::from_str("23923").unwrap();
    let srs_alpha = Fr::from_str("23728792").unwrap();

    let srs = SRS::<Bls12>::dummy(830564, srs_x, srs_alpha);

	let min = 0;
	let max = ((1u64 << 16) - 1) as u64;

    c.bench_function("Verify range proof", move |b| {
        // This may not be cryptographically safe, use
        // `OsRng` (for example) in production software.
        let rng = &mut thread_rng();

		let v = rng.gen_range(min, max);
	    let circuit = RangeProofDemo::<Bls12> {
	        v: Some(v),
			bit_size: 16,
	        _marker: PhantomData,
	    };

        let proof = Proof::<Bls12, Polynomial<Bls12>>::create_proof::< _, Basic>(&AdaptorCircuit(circuit.clone()), &srs).unwrap();

        b.iter(|| {
            let rng = thread_rng();
            let mut verifier = MultiVerifier::<Bls12, _, Basic, _>::new(AdaptorCircuit(circuit.clone()), &srs, rng).unwrap();

            for _ in 0..1 {
                verifier.add_proof(&proof, &[], |_, _| None);
            }
            assert_eq!(verifier.check_all(), true);
        })
    });
}

criterion_group! {
    name = sonic_verify;
    config = Criterion::default().sample_size(10);
    targets =
    range_proof_verifier,
}

criterion_main!(sonic_prove, sonic_verify);

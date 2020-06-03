#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;
use criterion::Criterion;

//extern crate rand_chacha;
extern crate curve25519_dalek;
extern crate merlin;
extern crate bulletproofs;

use rand::SeedableRng;
use rand::rngs::StdRng;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use merlin::Transcript;
use bulletproofs::r1cs::LinearCombination;

use bulletproofs_examples::r1cs_utils::{AllocatedScalar, constrain_lc_with_scalar};

pub const MIMC_ROUNDS: usize = 322;

pub fn mimc(
    xl: &Scalar,
    xr: &Scalar,
    constants: &[Scalar]
) -> Scalar
{
    assert_eq!(constants.len(), MIMC_ROUNDS);

    let mut xl = xl.clone();
    let mut xr = xr.clone();

    for i in 0..MIMC_ROUNDS {
        let tmp1 = xl + constants[i];
        let mut tmp2 = (tmp1 * tmp1) * tmp1;
        tmp2 += xr;
        xr = xl;
        xl = tmp2;
    }

    xl
}

pub fn mimc_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    left: AllocatedScalar,
    right: AllocatedScalar,
    mimc_rounds: usize,
    mimc_constants: &[Scalar],
    image: &Scalar
) -> Result<(), R1CSError> {
    let res_v = mimc_hash_2::<CS>(cs, left.variable.into(), right.variable.into(), mimc_rounds, mimc_constants)?;
    constrain_lc_with_scalar::<CS>(cs, res_v, image);
    Ok(())
}


pub fn mimc_hash_2<CS: ConstraintSystem>(cs: &mut CS,
                                         left: LinearCombination,
                                         right: LinearCombination,
                                         mimc_rounds: usize,
                                         mimc_constants: &[Scalar]) -> Result<LinearCombination, R1CSError> {
    let mut left_v = left;
    let mut right_v = right;

    for j in 0..mimc_rounds {
        // xL, xR := xR + (xL + Ci)^3, xL
        //let cs = &mut cs.namespace(|| format!("mimc round {}", j));

        let const_lc: LinearCombination = vec![(Variable::One(), mimc_constants[j])].iter().collect();

        let left_plus_const: LinearCombination = left_v.clone() + const_lc;

        let (l, _, l_sqr) = cs.multiply(left_plus_const.clone(), left_plus_const);
        let (_, _, l_cube) = cs.multiply(l_sqr.into(), l.into());

        let tmp = LinearCombination::from(l_cube) + right_v;
        right_v = left_v;
        left_v = tmp;
    }
    Ok(left_v)
}

fn mimc_prover(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, xl: Scalar, xr: Scalar, constants: &[Scalar], image: &Scalar) -> Result<(R1CSProof, (CompressedRistretto,CompressedRistretto)),R1CSError,> {
	let mut rng = rand::thread_rng();

    let mut prover_transcript = Transcript::new(b"MiMC");
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    let (com_l, var_l) = prover.commit(xl, Scalar::random(&mut rng));
    let (com_r, var_r) = prover.commit(xr, Scalar::random(&mut rng));

    let left_alloc_scalar = AllocatedScalar {
        variable: var_l,
        assignment: Some(xl),
    };

    let right_alloc_scalar = AllocatedScalar {
        variable: var_r,
        assignment: Some(xr),
    };

    assert!(mimc_gadget(&mut prover,
                        left_alloc_scalar,
                        right_alloc_scalar,
                        MIMC_ROUNDS,
                        &constants,
                        &image).is_ok());

	let proof = prover.prove(&bp_gens).unwrap();

    Ok((proof, (com_l, com_r)))
}

fn create_mimcproof_helper(c: &mut Criterion) {
    let label = format!("R1CS MiMC proof {} rounds", &MIMC_ROUNDS);

    c.bench_function(
        &label,
        |b| {
			let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

		    // Generate the MiMC round constants
		    let constants = (0..MIMC_ROUNDS).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
		    //let constants = (0..MIMC_ROUNDS).map(|i| Scalar::one()).collect::<Vec<_>>();

		    let pc_gens = PedersenGens::default();
		    let bp_gens = BulletproofGens::new(2048, 1);

			// Generate a random preimage and compute the image
		    let xl = Scalar::random(&mut test_rng);
		    let xr = Scalar::random(&mut test_rng);
		    let image = mimc(&xl, &xr, &constants);

            b.iter(|| {
                mimc_prover(&pc_gens, &bp_gens, xl, xr, &constants, &image).unwrap();
            })
        },
    );
}

criterion_group! {
    name = mimc_prove;
    config = Criterion::default().sample_size(10);
    targets =
    create_mimcproof_helper,
}

fn mimc_proof_verifier(proof: &R1CSProof, commitments: &(CompressedRistretto,CompressedRistretto), pc_gens: &PedersenGens, bp_gens: &BulletproofGens, constants: &[Scalar], image: &Scalar) -> Result<(), R1CSError> {
    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"MiMC");
    let mut verifier = Verifier::new(&mut verifier_transcript);

	let var_l = verifier.commit(commitments.0);
	let var_r = verifier.commit(commitments.1);

	let left_alloc_scalar = AllocatedScalar {
		variable: var_l,
		assignment: None,
	};

	let right_alloc_scalar = AllocatedScalar {
		variable: var_r,
		assignment: None,
	};

	assert!(mimc_gadget(&mut verifier,
						left_alloc_scalar,
						right_alloc_scalar,
						MIMC_ROUNDS,
						&constants,
						&image).is_ok());

    // Verifier verifies proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

fn verify_mimcproof_helper(c: &mut Criterion) {
    let label = format!("R1CS MiMC verify {} rounds", &MIMC_ROUNDS);

    c.bench_function(
        &label,
        |b| {
			let mut test_rng: StdRng = SeedableRng::from_seed([24u8; 32]);

		    // Generate the MiMC round constants
		    let constants = (0..MIMC_ROUNDS).map(|_| Scalar::random(&mut test_rng)).collect::<Vec<_>>();
		    //let constants = (0..MIMC_ROUNDS).map(|i| Scalar::one()).collect::<Vec<_>>();

		    let pc_gens = PedersenGens::default();
		    let bp_gens = BulletproofGens::new(2048, 1);

			// Generate a random preimage and compute the image
		    let xl = Scalar::random(&mut test_rng);
		    let xr = Scalar::random(&mut test_rng);
		    let image = mimc(&xl, &xr, &constants);

			let (proof, commitments) = mimc_prover(&pc_gens, &bp_gens, xl, xr, &constants, &image).unwrap();

            b.iter(|| {
                mimc_proof_verifier(&proof, &commitments, &pc_gens, &bp_gens, &constants, &image).unwrap();
            })
        },
    );
}

criterion_group! {
    name = mimc_verify;
    config = Criterion::default().sample_size(10);
    targets =
    verify_mimcproof_helper,
}

criterion_main!(mimc_prove, mimc_verify);

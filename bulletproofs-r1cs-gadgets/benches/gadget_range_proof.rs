#![allow(non_snake_case)]
#[macro_use]
extern crate criterion;
use criterion::Criterion;

use rand;
use rand::Rng;

use curve25519_dalek::scalar::Scalar;
use curve25519_dalek::ristretto::CompressedRistretto;

use merlin::Transcript;

use bulletproofs::r1cs::{R1CSError, R1CSProof, Prover, Verifier};
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs_examples::r1cs_utils::{AllocatedQuantity, positive_no_gadget, constrain_lc_with_scalar};

fn count_bits(number: u64) -> usize {
    let used_bits = 64 - number.leading_zeros();
    return used_bits as usize
}

fn range_proof_prover(pc_gens: &PedersenGens, bp_gens: &BulletproofGens, v: u64, min: u64, max: u64) -> Result<(R1CSProof, Vec<CompressedRistretto>,),R1CSError,> {
    let n = count_bits(max);

    let a = v - min;
    let b = max - v;

    // Prover's scope
    let mut comms = vec![];

    // Prover makes a `ConstraintSystem` instance representing a range proof gadget
    let mut prover_transcript = Transcript::new(b"BoundsTest");
    let mut rng = rand::thread_rng();

    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    // Constrain a in [0, 2^n)
    let (com_a, var_a) = prover.commit(a.into(), Scalar::random(&mut rng));
    let quantity_a = AllocatedQuantity {
        variable: var_a,
        assignment: Some(a),
    };
    assert!(positive_no_gadget(&mut prover, quantity_a, n).is_ok());
    comms.push(com_a);

    // Constrain b in [0, 2^n)
    let (com_b, var_b) = prover.commit(b.into(), Scalar::random(&mut rng));
    let quantity_b = AllocatedQuantity {
        variable: var_b,
        assignment: Some(b),
    };
    assert!(positive_no_gadget(&mut prover, quantity_b, n).is_ok());
    comms.push(com_b);

    // Constrain a+b to be same as max-min. This ensures same v is used in both commitments (`com_a` and `com_b`)
    constrain_lc_with_scalar(&mut prover, var_a + var_b, &(max-min).into());

    let proof = prover.prove(&bp_gens)?;

    Ok((proof, comms))
}

fn create_rangeproof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Single R1CS {}-bit rangeproof creation", n);

    c.bench_function(
        &label,
        |b| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(128, 1);

            let mut rng = rand::thread_rng();
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);

            let v = rng.gen_range(min, max);

            b.iter(|| {
                range_proof_prover(&pc_gens, &bp_gens, v, min, max).unwrap();
            })
        },
    );
}

fn create_rangeproof_n_8(c: &mut Criterion) {
    create_rangeproof_helper(8, c);
}

fn create_rangeproof_n_16(c: &mut Criterion) {
    create_rangeproof_helper(16, c);
}

fn create_rangeproof_n_32(c: &mut Criterion) {
    create_rangeproof_helper(32, c);
}

fn create_rangeproof_n_64(c: &mut Criterion) {
    create_rangeproof_helper(64, c);
}

fn range_proof_verifier(proof: &R1CSProof, commitments: &Vec<CompressedRistretto>, pc_gens: &PedersenGens, bp_gens: &BulletproofGens, n:usize, min: u64, max: u64) -> Result<(), R1CSError> {
    // Verifier makes a `ConstraintSystem` instance representing a merge gadget
    let mut verifier_transcript = Transcript::new(b"BoundsTest");
    let mut verifier = Verifier::new(&mut verifier_transcript);

    let var_a = verifier.commit(commitments[0]);
    let quantity_a = AllocatedQuantity {
        variable: var_a,
        assignment: None,
    };
    assert!(positive_no_gadget(&mut verifier, quantity_a, n).is_ok());

    let var_b = verifier.commit(commitments[1]);
    let quantity_b = AllocatedQuantity {
        variable: var_b,
        assignment: None,
    };
    assert!(positive_no_gadget(&mut verifier, quantity_b, n).is_ok());

    constrain_lc_with_scalar(&mut verifier, var_a + var_b, &(max-min).into());

    // Verifier verifies proof
    Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
}

fn verify_rangeproof_helper(n: usize, c: &mut Criterion) {
    let label = format!("Single R1CS {}-bit rangeproof verification", n);

    c.bench_function(
        &label,
        |b| {
            let pc_gens = PedersenGens::default();
            let bp_gens = BulletproofGens::new(128, 1);

            let mut rng = rand::thread_rng();
            let (min, max) = (0u64, ((1u128 << n) - 1) as u64);

            let v = rng.gen_range(min, max);
            let (proof, commitments) = range_proof_prover(&pc_gens, &bp_gens, v, min, max).unwrap();

            b.iter(|| {
                range_proof_verifier(&proof, &commitments, &pc_gens, &bp_gens, count_bits(max), min, max).unwrap();
            })
        },
    );
}

fn verify_rangeproof_n_8(c: &mut Criterion) {
    verify_rangeproof_helper(8, c);
}

fn verify_rangeproof_n_16(c: &mut Criterion) {
    verify_rangeproof_helper(16, c);
}

fn verify_rangeproof_n_32(c: &mut Criterion) {
    verify_rangeproof_helper(32, c);
}

fn verify_rangeproof_n_64(c: &mut Criterion) {
    verify_rangeproof_helper(64, c);
}

criterion_group! {
    name = create_rp;
    config = Criterion::default().sample_size(10);
    targets =
    create_rangeproof_n_8, create_rangeproof_n_16, create_rangeproof_n_32, create_rangeproof_n_64,
}
criterion_group! {
    name = create_vp;
    config = Criterion::default().sample_size(10);
    targets =
    verify_rangeproof_n_8, verify_rangeproof_n_16, verify_rangeproof_n_32, verify_rangeproof_n_64,
}

criterion_main!(create_rp, create_vp);

extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bulletproofs::r1cs::{ConstraintSystem, R1CSError, R1CSProof, Variable, Prover, Verifier};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use bulletproofs::r1cs::LinearCombination;
use std::cmp;

use crate::r1cs_utils::{AllocatedQuantity, positive_no_gadget, constrain_lc_with_scalar, chunk_gadget};

fn count_bits(number: u64) -> usize {
    let used_bits = 64 - number.leading_zeros();
    return used_bits as usize
}

// Chunk proof using the R1CS bulletproofs interface

#[cfg(test)]
mod tests {
    use super::*;
    use merlin::Transcript;

    #[test]
    fn test_chunk_proof_gadget() {
        use rand::rngs::OsRng;
        use rand::Rng;

        let mut rng: OsRng = OsRng::default();
        let max = 1 << 16;

        let v0 = rng.gen_range(0, max);
        let v1 = rng.gen_range(0, max);
        let v2 = rng.gen_range(0, max);
        let v3 = rng.gen_range(0, max);
        let v = v0 + (v1 << 16) + (v2 << 32) + (v3 << 48);

        println!("v is {}", &v);
        assert!(chunk_proof_helper(v, v0, v1, v2, v3).is_ok());
    }

    fn chunk_proof_helper(v: u64, v0: u64, v1: u64, v2: u64, v3: u64) -> Result<(), R1CSError> {
        let pc_gens = PedersenGens::default();
        let bp_gens = BulletproofGens::new(128, 1);

        let n = 16;
        println!("bit_size is {}", &n);

        let a = v0;
        let b = v1;
        let c = v2;
        let d = v3;
        let e = v;
        println!("a, b are {} {}", &a, &b);

        // Prover's scope
        let (proof, commitments) = {
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

            // Constrain c in [0, 2^n)
            let (com_c, var_c) = prover.commit(c.into(), Scalar::random(&mut rng));
            let quantity_c = AllocatedQuantity {
                variable: var_c,
                assignment: Some(c),
            };
            assert!(positive_no_gadget(&mut prover, quantity_c, n).is_ok());
            comms.push(com_c);

            // Constrain d in [0, 2^n)
            let (com_d, var_d) = prover.commit(d.into(), Scalar::random(&mut rng));
            let quantity_d = AllocatedQuantity {
                variable: var_d,
                assignment: Some(d),
            };
            assert!(positive_no_gadget(&mut prover, quantity_d, n).is_ok());
            comms.push(com_d);

            // Constrain b in [0, 2^n)
            let (com_e, var_e) = prover.commit(e.into(), Scalar::random(&mut rng));
            let quantity_e = AllocatedQuantity {
                variable: var_e,
                assignment: Some(e),
            };
            comms.push(com_e);

            assert!(chunk_gadget(&mut prover, quantity_a, quantity_b, quantity_c, quantity_d, quantity_e).is_ok());

            println!("For {} in ({}, {}, {}, {}), no of constraints is {}", v, v0, v1, v2, v3, &prover.num_constraints());
            println!("Prover commitments {:?}", &comms);
            let proof = prover.prove(&bp_gens)?;

            (proof, comms)
        };

        println!("Proving done");

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

        let var_c = verifier.commit(commitments[2]);
        let quantity_c = AllocatedQuantity {
            variable: var_c,
            assignment: None,
        };
        assert!(positive_no_gadget(&mut verifier, quantity_c, n).is_ok());

        let var_d = verifier.commit(commitments[3]);
        let quantity_d = AllocatedQuantity {
            variable: var_d,
            assignment: None,
        };
        assert!(positive_no_gadget(&mut verifier, quantity_d, n).is_ok());

        let var_e = verifier.commit(commitments[4]);
        let quantity_e = AllocatedQuantity {
            variable: var_e,
            assignment: None,
        };

        println!("Verifier commitments {:?}", &commitments);

        assert!(chunk_gadget(&mut verifier, quantity_a, quantity_b, quantity_c, quantity_d, quantity_e).is_ok());

        // Verifier verifies proof
        Ok(verifier.verify(&proof, &pc_gens, &bp_gens)?)
    }
}

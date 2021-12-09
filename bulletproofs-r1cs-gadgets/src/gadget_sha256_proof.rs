#![allow(non_snake_case)]
extern crate bigint;
extern crate bulletproofs;
extern crate curve25519_dalek;
extern crate merlin;
extern crate rand;

use bigint::uint::U256;
use bulletproofs::r1cs::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek::ristretto::CompressedRistretto;
use curve25519_dalek::scalar::Scalar;
use merlin::Transcript;
use rand::thread_rng;
use std::error::Error;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::time::{Duration, Instant};

pub const INPUT_SIZE: usize = 512;

pub fn getEquation(
    varArr: &Vec<Variable>,
    circuitConfigArr: &Vec<String>,
    mut i: usize,
) -> LinearCombination {
    let mut a: LinearCombination = LinearCombination::default();
    let mut n_terms = circuitConfigArr[i].parse::<i32>().unwrap();;
    i = i + 1;
    let mut term_cnt = 0;
    while term_cnt < n_terms {
        let mut varNum = circuitConfigArr[i].parse::<i32>().unwrap();
        let mut coeff = circuitConfigArr[i + 1].clone();
        let mut isNeg = false;
        if (circuitConfigArr[i + 1].starts_with('-')) {
            coeff = coeff[1..].to_string();

            isNeg = true;
        }

        let mut coeff_bits = [0u8; 32];
        // Convert from string to bigint and store as bits in coeff_bits
        bigint::uint::U256::from_dec_str(&coeff)
            .unwrap()
            .to_little_endian(&mut coeff_bits);

        //Convert from bits to Scalar
        let mut coeff_scalar = Scalar::from_bits(coeff_bits);

        if isNeg {
            a = a - coeff_scalar * varArr[varNum as usize];
        } else {
            a = a + coeff_scalar * varArr[varNum as usize];
        }

        i = i + 2;
        term_cnt = term_cnt + 1;
    }
    return a;
}
/*
    Add the R1CS circuit as mentioned in the circuitConfigArr
    Every R1CS circuit has three LinearCombination a, b, c.
    The constraint is a*b = c

    The way we input the R1CS circuit is as follows :
    <Total Variables>
    <number of terms in a>
    <variable number>
    <coefficient>
    .
    .
    <variable number>
    <coefficient>
    <number of terms in b>
    <variable number>
    <coefficient>
    .
    .
    <variable number>
    <coefficient>
    <number of terms in c>
    <variable number>
    <coefficient>
    .
    .
    <variable number>
    <coefficient>

    For Eg :
     The  circuit has following R1CS constraints :
    (2*x1) * (2*x2) = (x3 + x4)
    x1 * 3*x2 = -1*x4
    is as follows :

    4
    1
    1
    2
    1
    2
    2
    2
    3
    1
    4
    1
    1
    1
    1
    1
    2
    3
    1
    4
    -1
    --
    Explanation :
    The  circuit has following R1CS constraints :
    (2*x1) * (2*x2) = (x3 + x4)
    x1 * 3*x2 = -1*x4

    4 : Total 4 variables x1, x2, x3, x4 in addition to x0 which is 1
    1 : a has 1 term
    1 : Variable is x1
    2 : coefficient is 2
    1 : b has 1 term
    2 : the variable is x2
    2 : coefficient is 2
    2 : c has 2 terms
    3 : Variable x3
    1 : Coefficient of above variable x3 is 1
    4 : Variable x4
    1 : Coefficient of variable x4 is 1
    1 : a has 1 term
    1 : Variable x1
    1 : Coefficient of x1 is 1
    1 : b has 1 term
    2 : Variable x2
    3 : Coeficient of x2 is 1
    1 : c has 1 term
    4 : Variable x4
    -1 : coefficient of x4 is 1

*/
pub fn variable_argument_bigint<CS: ConstraintSystem>(
    cs: &mut CS,
    varArr: &Vec<Variable>,
    circuitConfigArr: &Vec<String>,
) -> Result<(), R1CSError> {
    // i maintains the current index in the circuitConfigArr which we are parsing
    let mut i: usize = 0;

    while i < circuitConfigArr.len() {

        let mut a = getEquation(varArr, circuitConfigArr, i);
        circuitConfigArr[i].parse::<i32>().unwrap();


        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;
        let mut b = getEquation(varArr, circuitConfigArr, i);

        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;
        let mut c = getEquation(varArr, circuitConfigArr, i);

        i = i + circuitConfigArr[i].parse::<usize>().unwrap() * 2 + 1;

        let (_, _, lhs) = cs.multiply(a, b);

        cs.constrain(lhs - c);
    }

    Ok(())
}

pub fn prove(
    witnessArr: &[u128],
    circuitConfigArr: &Vec<String>,
) -> Result<(R1CSProof, Vec<CompressedRistretto>), R1CSError> {

    // Convert witness from u128 array to Vec<Scalar>
    let witnessScalarArr: Vec<Scalar> = witnessArr.iter().map(|&x| x.into()).collect();

    let start = Instant::now();

    //  Create Generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    println!("Generators created at {:?} ", start.elapsed());

    // Create a new Prover Transcript
    let mut prover_transcript = Transcript::new(b"ShuffleTest");
    // Make a prover instance
    let mut prover = Prover::new(&pc_gens, &mut prover_transcript);

    println!("Prover object created at  {:?} ", start.elapsed());

    let mut rng = rand::thread_rng();

    // Maintain comArr : Vector of Commitments of all the variables
    let mut comArr: Vec<CompressedRistretto> = Vec::new();
    // Maintain varArr : Vector of all the variables
    let mut varArr: Vec<Variable> = Vec::new();

    for idx in 0..INPUT_SIZE {
        let (curCom, curVar) = prover.commit(witnessScalarArr[idx], Scalar::random(&mut rng));
        varArr.push(curVar.clone());
        comArr.push(curCom.clone());
    }
    for idx in INPUT_SIZE..witnessScalarArr.len() {
        let (curVar) = prover.allocate(Some(witnessScalarArr[idx])).unwrap();
        varArr.push(curVar.clone());
    }
    println!("All Commitments added at  {:?} ", start.elapsed());

    // Add the Circuit to the transcript from the circuitConfigArr
    variable_argument_bigint(&mut prover, &varArr,  circuitConfigArr)?;
    println!("Circuit added in the transcript at  {:?} ", start.elapsed());
	println!("No of constraints is {}, no of gates is {}", &prover.num_constraints(), &prover.num_multipliers());

    // Create a proof
    let proof = prover.prove(&bp_gens)?;
    //total_proving += start.elapsed();
    println!("prover.prove function completed at  {:?} ", start.elapsed());
	let serial = proof.to_bytes();
	println!("Proof size: {} bytes", serial.len());

    Ok((proof, comArr))
}

pub fn verify(
    proof: R1CSProof,
    ComArr: &Vec<CompressedRistretto>,
    variables_size : usize,
    circuitConfigArr: &Vec<String>,
) -> Result<(), R1CSError> {
    let start = Instant::now();

    //  Create Generators
    let pc_gens = PedersenGens::default();
    let bp_gens = BulletproofGens::new(65536, 1);
    println!("Generators created at  {:?} ", start.elapsed());

    // Create a new Verifier Transcript
    let mut verifier_transcript = Transcript::new(b"ShuffleTest");
    // Make a verifier instance
    let mut verifier = Verifier::new(&mut verifier_transcript);
    println!("Verifier object created at  {:?} ", start.elapsed());
    println!("ComArr.len = {:?}", ComArr.len() );
    let mut varArr: Vec<Variable> = Vec::new();

    for idx in 0..ComArr.len() {
        let curVar = verifier.commit(ComArr[idx]);
        varArr.push(curVar.clone());
    }
    for idx in INPUT_SIZE..variables_size {
        let (curVar) = verifier.allocate(None).unwrap();
        varArr.push(curVar.clone());
    }

    println!("All Commitments added at  {:?} ", start.elapsed());

    // Add gadget constraints to the verifier's constraint system
    variable_argument_bigint(&mut verifier, &varArr, circuitConfigArr)?;
    println!("Circuit added to transcript at  {:?} ", start.elapsed());
    // Verify the proof
    let op = verifier.verify(&proof, &pc_gens, &bp_gens);
    println!("verifier.verify function completed at {:?} ", start.elapsed());
    return op;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn variable_argument_bigint() -> Result<(), Box<dyn Error>> {
        let constraintFileName = "/home/dfaranha/projects/range-proofs/bulletproofs-r1cs-gadgets/SHA256_R1CS_constraints.txt";

        let mut circuitConfigArr: Vec<String> = Vec::new();
        let file = File::open(constraintFileName)?;
        let mut lines = BufReader::new(file).lines();
        let len = lines
            .nth(0)
            .expect("No line found at that position")
            .unwrap();
        for line in lines {
            let l = line.unwrap();
            circuitConfigArr.push(l.parse::<String>().unwrap());
        }
        let witnessFileName = "/home/dfaranha/projects/range-proofs/bulletproofs-r1cs-gadgets/SHA256_witness.txt";
        let mut witnessInput: Vec<u128> = Vec::new();
        witnessInput.push(1u128);
        let file = File::open(witnessFileName)?;
        let mut lines = BufReader::new(file).lines();

        for line in lines {
            let l = line.unwrap();
            witnessInput.push(l.parse::<u128>().unwrap());
        }
        println!("Witness Vector Size = {}", witnessInput.len());

        //assert!(variable_argument_bigint_helper(&witnessInput, &circuitConfigArr).is_ok());
        println!("{:?}", variable_argument_bigint_helper(&witnessInput, &circuitConfigArr).err());
        Ok(())
    }

    fn variable_argument_bigint_helper(
        witnessInput: &Vec<u128>,
        circuitConfigArr: &Vec<String>,
    ) -> Result<(), R1CSError> {

        let mut totalProvingTime = Duration::new(0, 0);
        let mut totalVerificationTime = Duration::new(0, 0);
        println!("============== Prover ====================");
        let proveStartTime = Instant::now();
        // Function which generates proof and commitmentVector given the witness and the circuitConfiguration.
        let (proof, comVec) = prove(witnessInput, circuitConfigArr)?;
        totalProvingTime += proveStartTime.elapsed();
        println!("Total time for prove function {:?} seconds", totalProvingTime);

        println!("============== Verifier ====================");
        let verifyStartTime = Instant::now();
        //Function to verify proof
        let op = verify(proof, &comVec, witnessInput.len() ,circuitConfigArr);
        totalVerificationTime += verifyStartTime.elapsed();
        println!("Total verifying time  {:?} seconds", totalVerificationTime);
        return op;
    }
}

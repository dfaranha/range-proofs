use bulletproofs::r1cs::{ConstraintSystem, R1CSError, Variable};
use curve25519_dalek::scalar::Scalar;
use bulletproofs::{BulletproofGens, PedersenGens};
use bulletproofs::r1cs::LinearCombination;

/// Represents a variable for quantity, along with its assignment.
#[derive(Copy, Clone, Debug)]
pub struct AllocatedQuantity {
    pub variable: Variable,
    pub assignment: Option<u64>
}

#[derive(Copy, Clone, Debug)]
pub struct AllocatedScalar {
    pub variable: Variable,
    pub assignment: Option<Scalar>
}

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn positive_no_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    v: AllocatedQuantity,
    bit_size: usize) -> Result<(), R1CSError> {
    let mut constraint_v = vec![(v.variable, -Scalar::one())];
    let mut exp_2 = Scalar::one();
    for i in 0..bit_size {
        // Create low-level variables and add them to constraints

        let (a, b, o) = cs.allocate_multiplier(v.assignment.map(|q| {
            let bit: u64 = (q >> i) & 1;
            ((1 - bit).into(), bit.into())
        }))?;

        // Enforce a * b = 0, so one of (a,b) is zero
        cs.constrain(o.into());

        // Enforce that a = 1 - b, so they both are 1 or 0.
        cs.constrain(a + (b - 1u64));

        constraint_v.push((b, exp_2));
        exp_2 = exp_2 + exp_2;
    }

    // Enforce that -v + Sum(b_i * 2^i, i = 0..n-1) = 0 => Sum(b_i * 2^i, i = 0..n-1) = v
    cs.constrain(constraint_v.iter().collect());

    Ok(())
}

/// Enforces that the quantity of v is in the range [0, 2^n).
pub fn chunk_gadget<CS: ConstraintSystem>(
    cs: &mut CS,
    u: AllocatedQuantity,
    v: AllocatedQuantity,
    x: AllocatedQuantity,
    y: AllocatedQuantity,
    z: AllocatedQuantity) -> Result<(), R1CSError> {
    let mut constraint_z = vec![(z.variable, -Scalar::one())];
    let exp_2 = Scalar::from((1 << 16) as u64);
    // Create low-level variables and add them to constraints
    constraint_z.push((u.variable, Scalar::one()));
    constraint_z.push((v.variable, exp_2));
    constraint_z.push((x.variable, exp_2 * exp_2));
    constraint_z.push((y.variable, exp_2 * exp_2 * exp_2));
    // Enforce that -z + Sum(b_i * 2^16i, i = 0..n-1) = 0 => Sum(b_i * 2^16i, i = 0..n-1) = z
    cs.constrain(constraint_z.iter().collect());

    Ok(())
}

/// Constrain a linear combination to be equal to a scalar
pub fn constrain_lc_with_scalar<CS: ConstraintSystem>(cs: &mut CS, lc: LinearCombination, scalar: &Scalar) {
    cs.constrain(lc - LinearCombination::from(*scalar));
}

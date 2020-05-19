# Range Proofs
This repository has tests and benchmarks for range proofs in multiple proof systems.
There are tests and benchmarked for values ranging from 8 bits to 64 bits, implemented in different ways.

We follow the classical approach to prove that a value `x` is such that `0 ≤ x ≤ 2ⁿ` for some power of 2.
A more detailed description can be found [here](https://github.com/lovesh/bulletproofs-r1cs-gadgets). There are many such examples there, with accompannying code for illustration.

## General Approach

The prover must satisfy 2 statements, `x ≥ 0` and `x ≤ 2ⁿ`. The second is equivalent to proving that `2ⁿ - x >= 0`, so both
can be actually done by proving that a value `v` lies in an interval `[0, max]` given commitments to `v` and `max - v`.
In both cases, the prover creates a bit-representation of `v` with `n` bits, so `v` must be in `[0, 2ⁿ)`.

Concretely, the prover creates an `n`-bit vector representation `[bₙ₋₁, bₙ₋₂, …b₁, b₀]` of `v` without revealing the bit vector to the verifier by
proving that each element of this vector is a bit in the right position. To prove each `bᵢ` is a bit, it is sufficient to prove `bᵢ*(aᵢ)=0` and that `aᵢ = 1-bᵢ`.
Finally, it is necessary to prove that the bit vector is a decomposition of `v` in base 2, and that the commitments of `v` and `max - v` use the same value `x`.

To allow very large values, we may also be interested in decomposing a value `x` in smaller chunks (for example, with 16 bit each) to prove that each chunk lies in the right interval and that the chunks are a proper decomposition of `x`.
We will refer to the latter as a *chunk gadget*.

## Bulletproofs

Bulletproofs allows two possibilities for implementing range proofs:
* A native one which can be used by a specialized interface and allows *aggregation* of many different proofs together
* A generic one following the approach outlined above using the recently-introduced, but still **experimental** *R1CS* interface.

There are performance trade-offs for the choices above. For example, let's check the cost of a single 16-bit range proof in both cases by running `cargo bench`:

```
Single R1CS 16-bit rangeproof creation                                                                           
                        time:   [5.2242 ms 5.4567 ms 5.6933 ms]
Single R1CS 16-bit rangeproof verification                                                                            
                        time:   [839.22 us 844.45 us 853.51 us]

Aggregated 16-bit rangeproof creation/1                                                                            
                        time:   [2.2794 ms 2.3137 ms 2.3615 ms]
Aggregated 16-bit rangeproof verification/1                                                                            
                        time:   [435.12 us 437.15 us 439.30 us]
```
The `builtin` proofs marked by `Aggregated` are much faster than the R1CS approach, both in terms of creation and verification, which is entirely expected. Notice that in the output above, an *aggregate proof*  has a single proof, as illustrated by the `/1`.

Actual aggregate range proofs amortize the cost of proving and verification across multiple proofs:

```
Aggregated 16-bit rangeproof creation/2                                                                            
                        time:   [4.3507 ms 4.3964 ms 4.4441 ms]
Aggregated 16-bit rangeproof creation/4                                                                           
                        time:   [8.2369 ms 8.2761 ms 8.2996 ms]
Aggregated 16-bit rangeproof creation/8                                                                           
                        time:   [16.009 ms 16.169 ms 16.312 ms]
Aggregated 16-bit rangeproof creation/16                                                                           
                        time:   [31.201 ms 31.295 ms 31.446 ms]
Aggregated 16-bit rangeproof creation/32                                                                           
                        time:   [60.213 ms 61.026 ms 62.673 ms]
Aggregated 16-bit rangeproof verification/2                                                                            
                        time:   [676.48 us 679.51 us 683.21 us]
Aggregated 16-bit rangeproof verification/4                                                                             
                        time:   [1.1984 ms 1.2240 ms 1.2520 ms]
Aggregated 16-bit rangeproof verification/8                                                                             
                        time:   [1.8006 ms 1.8219 ms 1.8501 ms]
Aggregated 16-bit rangeproof verification/16                                                                             
                        time:   [3.0971 ms 3.1307 ms 3.1736 ms]
Aggregated 16-bit rangeproof verification/32                                                                             
                        time:   [5.2860 ms 5.3539 ms 5.4408 ms]
```

There are also trade-offs in circuit size. For reference, a single 64-bit R1CS range proof gives `259` constraints, while a chunk gadget combining 4 chunks of 16 bits gives `133` constraints for the whole circuit instead.

Unfortunately, I was not able to combine the R1CS-level chunk gadget with the native range proofs in the library and *enjoy the best of both worlds*.

## SONIC

At the time of this writing, I am still unable to get the basic approach described above working in the [LayerX implementation of SONIC](https://github.com/LayerXcom/lx-sonic).

I keep getting a mal-formed verification key error when trying to do the individual bit proofs, which I can trace to the `bellman` crate, but cannot debug further.
This is harder due to a less mature codebase, without many examples and supporting documentation.

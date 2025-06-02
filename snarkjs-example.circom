pragma circom 2.1.6;

include "circomlib/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template PoseidonProof (nHashes) {
    signal input a;
    signal input b[nHashes];
    
    component hash = Poseidon(1);
    hash.inputs[0] <== a;
    //hash.out in b
    signal accumulator[nHashes];
    accumulator[0] <== hash.out - b[0];
    for(var i = 1; i < nHashes; i++){
        accumulator[i] <== accumulator[i-1] * (hash.out - b[i]);
    }
    signal output out;
    out <== accumulator[nHashes - 1];

}

component main { public [ b ] } = PoseidonProof(3);

/* INPUT = {
    "a": "5",
    "b": ["77","23","21"]
} */
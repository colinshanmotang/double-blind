pragma circom 2.1.6;

include "../node_modules/circomlib/circuits/poseidon.circom";

template smallRSAProof() {
    signal input d;
    signal input e;
    signal input n; 
}

template Hash() {
    // TODO: change hash
    signal input in;
    signal output out;
    component h = Poseidon();
    h.inputs[0] <== in;
    out <== h.out
}
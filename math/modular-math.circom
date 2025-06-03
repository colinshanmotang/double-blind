
include "../node_modules/circomlib/circuits/comparators.circom";
// Given nonnegative a and m returns a mod m
template ModularReduction(nBits) {
    signal input a;
    signal input m;
    signal output out;
    signal q;
    out <-- a % m;
    q <-- a \ m;
    q * m === a - out;

    component geqzero = GreaterEqThan(nBits);
    geqzero.in[0] <== out;
    geqzero.in[1] <== 0;
    geqzero.out === 1;

    component ltm = LessThan(nBits);
    ltm.in[0] <== out;
    ltm.in[1] <== m;
    ltm.out === 1;
}

template ModularAddition(nBits) {
    signal input a;
    signal input b;
    signal input m;
    signal output c;
    signal int1;
    int1 <== a+b;
    component modRed = ModularReduction(nBits);
    modRed.a <== int1;
    modRed.m <== m;
    c <== modRed.out;
}

template ModularMultiplication(nBits) {
    signal input a;
    signal input b;
    signal input m;
    signal output out;
    signal int1;
    int1 <== a*b;
    component modRed = ModularReduction(nBits);
    modRed.a <== int1;
    modRed.m <== m;
    out <== modRed.out;
}

template ModularExponentiation(nExpBits, nBits) {
    signal input base;
    signal input exp[nExpBits];
    signal input m;
    signal multiplier[nExpBits];
    signal tmp[nExpBits];
    signal tmpRed[nExpBits];
    signal tmp2[nExpBits+1];
    signal tmp2Red[nExpBits+1];
    signal t[nExpBits];
    signal output out;

    component modRed[nExpBits];
    component modRed2[nExpBits];

    for (var i = 0; i < nExpBits; i++) {
        exp[i] * (1 - exp[i]) === 0;
    }

    tmp2Red[0] <== 1;
    for (var i = 0; i < nExpBits; i++) {
        tmp[i] <== tmp2Red[i] * tmp2Red[i];
        modRed[i] = ModularReduction(nBits);
        modRed[i].a <== tmp[i];
        modRed[i].m <== m;
        tmpRed[i] <== modRed[i].out;
        multiplier[i] <== 1 + (base-1) * exp[nExpBits - 1 - i];
        tmp2[i] <== tmpRed[i] * multiplier[i];
        modRed2[i] = ModularReduction(nBits);
        modRed2[i].a <== tmp2[i];
        modRed2[i].m <== m;
        tmp2Red[i+1] <== modRed2[i].out;
    }
    out <== tmp2Red[nExpBits];
}

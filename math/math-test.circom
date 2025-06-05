include "./modular-math.circom";

template ModularMathTest(nBits, addTests, mulTests, expTests, nExpBits) {
    signal input add_a[addTests];
    signal input add_b[addTests];
    signal input add_m[addTests];
    signal output add_out[addTests];
    component modularAddition[addTests];

    for (var i = 0; i < addTests; i++){
        modularAddition[i] = ModularAddition(nBits);
        modularAddition[i].a <== add_a[i];
        modularAddition[i].b <== add_b[i];
        modularAddition[i].m <== add_m[i];
        add_out[i] <== modularAddition[i].out;
    }
    

    signal input mul_a[mulTests];
    signal input mul_b[mulTests];
    signal input mul_m[mulTests];
    signal output mul_out[mulTests];
    component modularMultiplication[mulTests];

    for (var i = 0; i < mulTests; i++){
        modularMultiplication[i] = ModularMultiplication(nBits);
        modularMultiplication[i].a <== mul_a[i];
        modularMultiplication[i].b <== mul_b[i];
        modularMultiplication[i].m <== mul_m[i];
        mul_out[i] <== modularMultiplication[i].out;
    }

    signal input exp_base[expTests];
    signal input exp_exp[expTests][nExpBits];
    signal input exp_m[expTests];
    signal output exp_out[expTests];
    component modularExponentiation[expTests];

    for (var i = 0; i < expTests; i++){
        modularExponentiation[i] = ModularExponentiation(nExpBits, nBits);
        modularExponentiation[i].base <== exp_base[i];
        modularExponentiation[i].exp <== exp_exp[i];
        modularExponentiation[i].m <== exp_m[i];
        exp_out[i] <== modularExponentiation[i].out;
    }
}
include "./modular-math.circom";

template ModularMathTest(nBits, addTests) {
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
        add_out[i] <== modularAddition[i].c;
    }
}
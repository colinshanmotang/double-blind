pragma circom 2.1.6;

//include "circomlib/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";
//include "circomlib/compconstant.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Mod () {
    signal input modulus;
    signal input a;
    signal output residue;
    residue <-- a % modulus;
    signal quotient <-- a \ modulus; 
    // the % and \ operators treat both arguments as nonneg ints
    residue + (quotient * modulus) === a;
    component modulus_size_check = Num2Bits(126);
    component quotient_size_check = Num2Bits(126);
    modulus_size_check.in <== modulus;
    quotient_size_check.in <== quotient;
    component residue_size_check_lower = Num2Bits(126);
    residue_size_check_lower.in <== residue;
    component residue_size_check_upper = Num2Bits(126);
    residue_size_check_upper.in <== modulus - 1 - residue;
}

template MultiplyMod (){
    signal input modulus;
    signal input a;
    signal input b;
    signal output product;
    //return a*b mod modulus
    component mod_component = Mod();
    mod_component.modulus <== modulus;
    mod_component.a <== a * b;
    product <== mod_component.residue;
}

template ToyRSASigVer (nKeys) {
    signal input msg;
    signal input key;
    signal input keylist[nKeys]; //public keys
    signal input sig;
    //size check msg, key
    component msg_size_check = Num2Bits(126);
    component key_size_check = Num2Bits(126);
    msg_size_check.in <== msg;
    key_size_check.in <== key;

    //check sig = Sign(msg, key)
    //take e = 65537
    //sig = msg^65537 (mod key)
    signal powers[16];
    component powers_multiply[16];
    powers_multiply[0] = MultiplyMod();
    powers_multiply[0].modulus <== key;
    powers_multiply[0].a <== msg;
    powers_multiply[0].b <== msg;
    powers[0] <== powers_multiply[0].product;
    for(var i = 1; i < 16; i++){
        powers_multiply[i] = MultiplyMod();
        powers_multiply[i].modulus <== key;
        powers_multiply[i].a <== powers[i-1];
        powers_multiply[i].b <== powers[i-1];
        powers[i] <== powers_multiply[i].product;
    }
    component powers_multiply_final = MultiplyMod();
    powers_multiply_final.modulus <== key;
    powers_multiply_final.a <== powers[15];
    powers_multiply_final.b <== msg;
    sig === powers_multiply_final.product;
    
    //check key in keylist
    signal accumulator[nKeys];
    accumulator[0] <== keylist[0] - key;
    for(var i = 1; i < nKeys; i++){
        accumulator[i] <== accumulator[i-1] * (keylist[i] - key);
    }
    accumulator[nKeys-1] === 0;
    
}

component main { public [ msg,  keylist] } = ToyRSASigVer(3);

/* INPUT = {
    "msg": "3",
    "key": "10",
    "sig": "3",
    "keylist": ["10","11","12"]
} */
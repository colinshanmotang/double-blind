pragma circom 2.1.6;

//include "circomlib/bitify.circom";
include "bigint.circom";
//include "https://github.com/0xPARC/circom-bigint/blob/main/bigint_func.circom";

function num_registers(x,MAX_LEN){
    for(var i = MAX_LEN-1; i >= 0; i--){
        if(x[i] != 0){
            return i+1;
        }
    }
    return 0;
}

//a 4096-bit number is represented using k=34 registers of n=121 bits each
//In Mod and MultiplyMod, all signals with keyword "input" are assumed to be correctly formatted (i.e. satisfies sizecheck)
template Mod(n,k){
    signal input modulus[k];
    signal input a[2*k];
    signal output residue[k];
    signal sig_quotient[2*k];
    var long_div_out[2][100];
    var modulus_len = num_registers(modulus,k);
    long_div_out = long_div(n,modulus_len,2*k-modulus_len,a,modulus);
    var remainder[100];
    remainder = long_div_out[1];
    var quotient[100];
    quotient = long_div_out[0];
    for(var i = 0; i < k; i++){
        residue[i] <-- remainder[i];
    }
    component residue_sizecheck[k];
    for(var i = 0; i < k; i++){
        residue_sizecheck[i] = Num2Bits(n);
        residue_sizecheck[i].in <== residue[i];
    }
    //check residue < modulus
    component residue_lt_modulus = BigLessThan(n,k);
    for(var i = 0; i < k; i++){
        residue_lt_modulus.a[i] <== residue[i];
        residue_lt_modulus.b[i] <== modulus[i];
    }
    residue_lt_modulus.out === 1;
    for(var i = 0; i < 2*k; i++){
        sig_quotient[i] <-- quotient[i];
    }
    component sig_quotient_sizecheck[2*k];
    for(var i = 0; i < 2*k; i++){
        sig_quotient_sizecheck[i] = Num2Bits(n);
        sig_quotient_sizecheck[i].in <== sig_quotient[i]; 
    }
    signal product[3*k];
    component mult = BigMult(n,2*k);
    for(var i = 0; i < 2*k; i++){
        if(i < k){
            mult.a[i] <== modulus[i];
        }
        else{
            mult.a[i] <== 0;
        }
        mult.b[i] <== sig_quotient[i];
    }
    for(var i = 0; i < 3*k; i++){
        product[i] <== mult.out[i];
    }
    signal sum[3*k+1];
    component add = BigAdd(n,3*k);
    for(var i = 0; i < 3*k; i++){
        add.a[i] <== product[i];
        if(i<k){
            add.b[i] <== residue[i];
        }
        else{
            add.b[i] <== 0;
        }
    }
    for(var i=0; i< 3*k + 1; i++){
        sum[i] <== add.out[i];
    }
    for(var i=0; i< 3*k+1; i++){
        if(i<2*k){
            sum[i] === a[i];
        }
        else{
            sum[i] === 0;
        }
    }
}

template MultiplyMod(n,k){
    signal input a[k];
    signal input b[k];
    signal input modulus[k];
    signal output residue[k];
    signal product[2*k];
    component mult = BigMult(n,k);
    for(var i=0; i<k; i++){
        mult.a[i] <== a[i];
        mult.b[i] <== b[i];
    }
    for(var i=0; i<2*k; i++){
        product[i] <== mult.out[i];
    }
    component mod = Mod(n,k);
    for(var i = 0; i < k; i++){
        mod.modulus[i] <== modulus[i];
    }
    for(var i=0; i < 2*k; i++){
        mod.a[i] <== product[i];
    }
    for(var i=0; i<k; i++){
        residue[i] <== mod.residue[i];
    }
}

template RSASigVerify (n,k,nKeys) {
    signal input msg[k];
    signal input key[k];
    signal input keylist[nKeys][k]; //public keys
    signal input sig[k];
    //size check sig, key (the private inputs)
    component sig_sizecheck[k];
    for(var i=0; i<k; i++){
        sig_sizecheck[i] = Num2Bits(n);
        sig_sizecheck[i].in <== sig[i];
    }
    component key_sizecheck[k];
    for(var i=0; i<k; i++){
        key_sizecheck[i] = Num2Bits(n);
        key_sizecheck[i].in <== key[i];
    }
    //public inputs are assumed to be correctly formatted
    
    //check sig = Sign(msg, key)
    //take e = 65537
    //msg = sig^65537 (mod key)
    signal powers[16][k];
    component powers_multiply[16];
    powers_multiply[0] = MultiplyMod(n,k);
    for(var i=0; i<k; i++){
        powers_multiply[0].modulus[i] <== key[i];
        powers_multiply[0].a[i] <== sig[i];
        powers_multiply[0].b[i] <== sig[i];
    }
    for(var i=0; i<k; i++){
        powers[0][i] <== powers_multiply[0].residue[i];
    }
    for(var p = 1; p < 16; p++){
        powers_multiply[p] = MultiplyMod(n,k);
        for(var i=0; i<k; i++){
            powers_multiply[p].modulus[i] <== key[i];
            powers_multiply[p].a[i] <== powers[p-1][i];
            powers_multiply[p].b[i] <== powers[p-1][i];
        }
        for(var i=0; i<k; i++){
            powers[p][i] <== powers_multiply[p].residue[i];
        }
    }
    component powers_multiply_final = MultiplyMod(n,k);
    for(var i=0; i<k; i++){
        powers_multiply_final.modulus[i] <== key[i];
        powers_multiply_final.a[i] <== powers[15][i];
        powers_multiply_final.b[i] <== sig[i];
    }
    component eq = BigIsEqual(k);
    for(var i=0; i<k; i++){
        eq.in[0][i] <== msg[i];
        eq.in[1][i] <== powers_multiply_final.residue[i];
    }
    eq.out === 1;
    
    //check key in keylist
    signal accumulator[nKeys+1];
    accumulator[0] <== 0;
    component keyMembership[nKeys];
    for(var j = 0; j < nKeys; j++){
        keyMembership[j] = BigIsEqual(k);
        for(var i=0; i<k; i++){
            keyMembership[j].in[0][i] <== key[i];
            keyMembership[j].in[1][i] <== keylist[j][i];
        }
        accumulator[j+1] <== accumulator[j] + keyMembership[j].out;
    }
    //need accumulator[nKeys] to be nonzero
    component isz = IsZero();
    isz.in <== accumulator[nKeys];
    isz.out === 0;
}

component main { public [ msg, keylist ] } = RSASigVerify(121,34,10);

/* INPUT = {
    "msg": ["1","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"],
    "key": ["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
    "keylist":[["1","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["2","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["3","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["4","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["5","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["6","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["7","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["8","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["9","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"],
["10","2","3","4","5","6","7","8","9","10","11","12","13","14","15","16","17","18","19","20","21","22","23","24","25","26","27","28","29","30","31","32","33","34"]],
    "sig": ["1","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0","0"]
} */
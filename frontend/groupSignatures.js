//import { Sign } from 'crypto-browserify';
import * as SignatureProcessing from './signature-processing.js';

const proofComponent = document.getElementById('proof');
const publicComponent = document.getElementById('public');
const resultComponent = document.getElementById('result');
const inputSignature = document.getElementById('input-signature');
const inputPublicKeys = document.getElementById('input-public-keys');
const inputPublic = document.getElementById('input-public');
const bGenProof = document.getElementById("bGenProof");
const vProof = document.getElementById("VerifyProof");

bGenProof.addEventListener("click", calculateProof);
vProof.addEventListener("click", verifyProof);

async function calculateProof() {
    const publicKeys = inputPublicKeys.value.split("\n");
    console.log(publicKeys);
    for (const publicKey of publicKeys){
        console.log(SignatureProcessing.parseSSHRSAPublicKey(publicKey));
    }
    //const { proof, publicSignals } =
      //await snarkjs.groth16.fullProve( JSON.parse(inputInputs.value), "toyrsa_js/toyrsa.wasm", "toyrsa_0001.zkey");

    //proofComponent.innerHTML = JSON.stringify(proof, null, 1);

    //publicComponent.innerHTML = JSON.stringify(publicSignals, null, 1);
    
}

async function verifyProof () {
    const vkey = await fetch("verification_key-toyrsa.json").then( function(res) {
        return res.json();
    });

    const publicSignals = JSON.parse(inputPublic.value);

    const proof = JSON.parse(inputProof.value);
    //console.log(vkey, publicSignals, proof);
    const res = await snarkjs.groth16.verify(vkey, publicSignals, proof);
    //console.log("success verify");

    resultComponent.innerHTML = res;
}
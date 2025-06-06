'use client';

import { useEffect, useRef } from 'react';
import * as SignatureProcessing from './lib/signature-processing';

function bigint_to_registers(n, k, bi) {
    //k registers, of size n each
    //little-endian
    let result = [];
    let bi_temp = bi;
    for(let i =0; i < k; i++){
        result.push((bi_temp % (1n << n)).toString());
        bi_temp = bi_temp / (1n << n);
    }
    return result;
}


export default function Home() {
  const inputSignatureRef = useRef(null);
  const inputMessageRef = useRef(null);
  const inputPublicKeysRef = useRef(null);
  const inputProofRef = useRef(null);
  const inputPublicRef = useRef(null);
  const modulusLengthRef = useRef(null);
  const inputModulusLengthRef = useRef(null);
  const proofRef = useRef(null);
  const publicRef = useRef(null);
  const resultRef = useRef(null);

  useEffect(() => {
    // Add window.global for snarkjs
    window.global = window;
    
    // Load snarkjs
    const script = document.createElement('script');
    script.src = '/snarkjs.min.js';
    document.body.appendChild(script);

    return () => {
      document.body.removeChild(script);
    };
  }, []);

  const calculateProof = async () => {
    const signature_info = SignatureProcessing.parseRSA_SHA2_512Signature(inputSignatureRef.current.value);
    const keylist_array = inputPublicKeysRef.current.value.split("\\");
    let keylist_registers = [];
    for (let i = 0; i < keylist_array.length; i++){
        keylist_registers.push(bigint_to_registers(121n,34,SignatureProcessing.parseSSHRSAPublicKey(keylist_array[i]).modulusBigInt));
    }
    const zero_register = Array(34).fill("0");
    for (let i = keylist_array.length; i < 10; i++){
        keylist_registers.push(zero_register);
    }
    
    const inputJson = {
        "msg":bigint_to_registers(121n,34,SignatureProcessing.generatePKCS1BigInt(inputMessageRef.current.value, "file", "SHA-512", signature_info.modulusLength)),
        "key":bigint_to_registers(121n,34,signature_info.modulusBigInt),
        "sig":bigint_to_registers(121n,34,signature_info.signatureBigInt),
        "keylist":keylist_registers
    }
    console.log(inputJson);
    modulusLengthRef.current.innerHTML = JSON.stringify(signature_info.modulusLength);

    const { proof, publicSignals } =
      await window.snarkjs.groth16.fullProve( inputJson, "rsa-test_js/rsa-test.wasm", "rsa-test_0001.zkey");

    proofRef.current.innerHTML = JSON.stringify(proof, null, 1);

    publicRef.current.innerHTML = JSON.stringify(publicSignals, null, 1);

  };

  const verifyProof = async () => {
    const keylist_array = inputPublicKeysRef.current.value.split("\\");
    let keylist_registers = [];
    for (let i = 0; i < keylist_array.length; i++){
        keylist_registers.push(bigint_to_registers(121n,34,SignatureProcessing.parseSSHRSAPublicKey(keylist_array[i]).modulusBigInt));
    }
    const zero_register = Array(34).fill("0");
    for (let i = keylist_array.length; i < 10; i++){
        keylist_registers.push(zero_register);
    }
    const modulusLength = parseInt(inputModulusLengthRef.current.value);
    const msg_register = bigint_to_registers(121n,34,SignatureProcessing.generatePKCS1BigInt(inputMessageRef.current.value, "file", "SHA-512", modulusLength));

    const vkey = await fetch("verification_key-rsa-test.json").then(function(res) {
      return res.json();
    });

    const publicSignals = JSON.parse(inputPublicRef.current.value);
    const proof = JSON.parse(inputProofRef.current.value);
    //verify msg
    let res = true;
    for (let i = 0; i < 34; i++){
        if (publicSignals[i] !== msg_register[i]){
            res = false;
            break;
        }
    }
    //verify keylist
    if (res){
        for (let j = 0; j < keylist_registers.length * 34; j++){
            if (publicSignals[j+34] !== keylist_registers[Math.floor(j/34)][j%34]){
                res = false;
                break;
            }
        }
    }
    if (res){
        res = await window.snarkjs.groth16.verify(vkey, publicSignals, proof);
    }
    resultRef.current.innerHTML = res;
  };

  return (
    <main className="p-8">
      <h1 className="text-2xl font-bold mb-4">RSA group signature verifier</h1>

      <div className="space-y-4">
        <div>
          <textarea
            ref={inputSignatureRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input signature here (enclosed in -----BEGIN SSH SIGNATURE----- and -----END SSH SIGNATURE-----)"
          />
        </div>

        <div>
          <textarea
            ref={inputMessageRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input message here (note: may need to insert final newline if you signed on command line)"
          />
        </div>


        <div>
          <textarea
            ref={inputPublicKeysRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input public keys here, separated by \ (must input at least 1 public key)"
          />
          
          <br/> Example: <br/>
          <code>
          ssh-rsa <br/> AAAA <br/> \ <br/> ssh-rsa <br/> AAAB <br/> \ <br/> ...
          </code>
        </div>

        <button
          onClick={calculateProof}
          className="px-4 py-2 bg-blue-500 text-white rounded hover:bg-blue-600"
        >
          Create proof
        </button>

        <div>
          <textarea
            ref={inputProofRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input proof here"
          />
        </div>

        <div>
          <textarea
            ref={inputPublicRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input public inputs here"
          />
        </div>

        <div>
          <textarea
            ref={inputModulusLengthRef}
            className="w-full p-2 border rounded"
            rows={1}
            placeholder="Input modulus length here"
          />
        </div>

        <button
          onClick={verifyProof}
          className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
        >
          Verify proof
        </button>

        <div className="space-y-4">
         <pre className="bg-gray-100 p-4 rounded">
            Modulus length (bytes): <br />
            <code ref={modulusLengthRef}></code>
          </pre>

          <pre className="bg-gray-100 p-4 rounded">
            Proof: <br />
            <code ref={proofRef}></code>
          </pre>

          <pre className="bg-gray-100 p-4 rounded">
            Public inputs: <br />
            <code ref={publicRef}></code>
          </pre>

          <pre className="bg-gray-100 p-4 rounded">
            Result: <br />
            <code ref={resultRef}></code>
          </pre>
        </div>
      </div>
    </main>
  );
}

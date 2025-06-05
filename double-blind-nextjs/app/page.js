'use client';

import { useEffect, useRef } from 'react';
import * as SignatureProcessing from './lib/signature-processing';

export default function Home() {
  const inputSignatureRef = useRef(null);
  const inputPublicKeysRef = useRef(null);
  const inputProofRef = useRef(null);
  const inputPublicRef = useRef(null);
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
    const publicKeys = inputPublicKeysRef.current.value.split("\n");
    console.log(publicKeys);
    for (const publicKey of publicKeys) {
      console.log(SignatureProcessing.parseSSHRSAPublicKey(publicKey));
    }
  };

  const verifyProof = async () => {
    const vkey = await fetch("verification_key-toyrsa.json").then(function(res) {
      return res.json();
    });

    const publicSignals = JSON.parse(inputPublicRef.current.value);
    const proof = JSON.parse(inputProofRef.current.value);
    const res = await window.snarkjs.groth16.verify(vkey, publicSignals, proof);
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
            placeholder="Input signature here"
          />
        </div>

        <div>
          <textarea
            ref={inputPublicKeysRef}
            className="w-full p-2 border rounded"
            rows={5}
            placeholder="Input public keys here"
          />
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

        <button
          onClick={verifyProof}
          className="px-4 py-2 bg-green-500 text-white rounded hover:bg-green-600"
        >
          Verify proof
        </button>

        <div className="space-y-4">
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

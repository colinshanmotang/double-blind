import assert from 'assert';
import {RSASignatureAnalyzer} from './claude-parses-openssh-signatures.js';
import createHash from 'crypto';


function parseRSA_SHA2_512Signature(rawSignature){

    const analyzer = new RSASignatureAnalyzer();
    const result = analyzer.analyzeRawSignature(rawSignature);

    // Assert sha512 hash
    assert(result.signatureAnalysis.signatureFormat.hashAlgorithm === 'sha512');

    // Assert rsa-sha2-512 algorithm
    assert(result.signatureAnalysis.signatureFormat.signatureAlgorithm === 'rsa-sha2-512');

    // Assert 4096-bit
    assert(result.signatureAnalysis.rsaComponents.modulusLength === 512); 
    return {
        modulusBigInt: result.signatureAnalysis.rsaComponents.modulusBigInt,
        exponentBigInt: result.signatureAnalysis.rsaComponents.exponentBigInt,
        signatureBigInt: result.signatureAnalysis.signature.bigInt
    }
}

function generatePKCS1BigInt(message, namespace, hashAlgorithm, modulusByteLength){
    const analyzer = new RSASignatureAnalyzer();
    const toSign = analyzer.constructSSHSignatureBlock(message, namespace, hashAlgorithm);
    const paddedData = analyzer.pkcs1Encode(toSign, modulusByteLength, hashAlgorithm);
    //console.log(paddedData.toString('hex'));
    return analyzer.bufferToBigInt(paddedData);
}

function generateDefaultPKCS1BigInts(){
    const message = "E PLURIBUS UNUM; DO NOT SHARE";
    const namespace = "double-blind.xyz";
    const hashAlgorithm = "SHA-512";
    const modulusByteLength = 512;
    return [
        generatePKCS1BigInt(message + "\n", namespace, hashAlgorithm, modulusByteLength),
        generatePKCS1BigInt(message + "\r\n", namespace, hashAlgorithm, modulusByteLength)
    ]
}

function parseSSHRSAPublicKey(rawPublicKey){
    const analyzer = new RSASignatureAnalyzer();
    const result = analyzer.parseRawSSHPublicKey(rawPublicKey);
    assert.equal(result.algorithm, "ssh-rsa");
    return {
        modulusBigInt: result.modulusBigInt,
        exponentBigInt: result.exponentBigInt
    }
}

const rawSig = `-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBALiE08Ltl3Rz5Irk/auYYW
5oyfPKrtfgorcMj/+meP4F8cqsnbWZN6P3hXgAmkEowUo/3h8QJRj1Ld5K3X8LQj8Ubjhu
rxdnYW7BkZP14h/KTY5T4FJi8GbEJUC8dCQ2ijnlmz2K/EVE7GzJ9S06PsI6aPatxfRsst
PdlhnnLrYJEe7P0jbmOB4rsT3WgJRl3INFC3pKdR65u1dGftRVZVIuU9mH9BmwxPc4GuRV
dN3XoFv8jLIvnET6hmo59r+13LeLDeYGDsVKGoh2JwwfoRjJzb99+AAykE11ETi97aPxAj
0VqRu4T35LrgprYOF1kRkwLgUgICSZ81LTQET5dSPSmJax+XFTiXCAvPSJ4EJbXNe//MuH
UedKzhjyorViCIPRj9WX+HpkGHakF3Xfq7T6q/MQh9NABEZVUUlZAVnJCVZlcf3zK+kRLb
+S1AJVigHB6f2PaWR7BEiRJXyP0BxbAHxM/LjEqacbi5gspUbh0K/p6/dDy/BvxOTE2P2L
wnwkAnq/O+V6J5X91L7s2oExlUUowsQyKDEp4e96iWZo71ufQF+K19373vFm9Rni+4CSUG
eXc7fwcV2XE5GvKoc7NTS2ly9IPq+LbNRlb7ffdVHbEcUy//HIcod07bhhOG9MyfgAkwgG
nLREm/hWxNK2b0ra4b3x6rU64FdXoZGLAAAAEGRvdWJsZS1ibGluZC54eXoAAAAAAAAABn
NoYTUxMgAAAhQAAAAMcnNhLXNoYTItNTEyAAACAHZMWfhAgL46al9AgXoZN7Ug9IP4ifP7
+bs92sPKjucnUXNpLPsu6zKPkwu1F75HM+M6S1MiJvFC0WFbc6jNIVV+GRa/ok5sqMFwSq
xmEHEJDLXRvQWGqgDbiPpznnvSKpq+46UYD9uqFm3+qwrr4a4iad5kVj8y3mrYbx3LTf6y
BLpqXAe6GMkDaIpiJtQy6VYeSi/LlNMnHJAc6hnwdt5heITDbgqfrRKHYWKMTM5ov0GsQB
liHsxtD6169pw8/hqtrMLB8zeOSPUozFXJdnXrfdFJCMC+8z8NlbdmAG+D1huxTFVaA6Rl
9u3TBx3H7km+FasO07j6kMLMsnXSSSrjWWNE8x3bAHEtA2LrzVzZdNmetyAwaBGRuX7twW
a3OFpx27h9DLbU0WNiCCJZLqFyfxjqsgbFwSUE2c2ciRf4ieV8lk5rrUhcgf6ycfexKKQV
+PujvpJ+3MzBlKbCbo48DsERiAM4mtTcWOAYl4tlY8W5ahtlGDfSvQbucw6FwCWumrvPFs
cyAQ/CKN1XJ5segzA1U4O4Rdbnt4IEW/vei2Fi21eNiR55J5peUthAaLqbr6JRBKEVg+Km
Ppxk5rL0ryZ9LK6WBBt36sE0yOIF3RonErbqt2zuQdWm4/rXVYS7qxrhNR527AMSOzvwHY
aRLB2tnjkAMjgc2Ypcb76r
-----END SSH SIGNATURE-----`;

const rawPublicKey = 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDaUZ0plDmE7LTS55y4DleF3KJGgI2qG9NHqtjWK52ZsR8ayt6zdB11oSzAxhhcT8YhDWM8v68VNTmc15bkPnCp1nrsntBJ/nrwarB5P3LLsOQP6GkhaL/wy/RYRHImYpczPhWfVev2G6AQv3SJbsooVzgbjHIcmJBSMrULHhA8yd9NcU/XTLQxwpTpnfqxO+I2IhxJMJdxfITGEzll94eJUu76rCfWFLEUxwUxFPxc6YduCeM6rwQDCrSVqUgk/hHitD/0FbQUNvwpPF8HDcsUzJEecdR3SuuqmbW+AXBqbut74CH7wWXE4jB0/0aKLIMNEcY0ypH3efopPqM/eTamg9PBAnfc7fyNmbNg5GZGEzJnxykcVD6q79dBnWqOvlls3eGss6EEHciAvrY42JJw4SX6zr0/2o70O8w/vE9uDwg+rd7nw1zilwukk4fdoSI/JZS3bmpjA+TJ4cOVfLe1/zXvOqlLszUWXntIbsOz8hpK15TpKK7wLrIwVQcd5JEJDDAxHbSPn0L503zho7Byar8Z74MYfCWfc65aO4HSFQO6zGo036ddsqRDHZarWvwLlGAtNHDRKBcPCQ7MoHZi7YTJ9w4GyLB1xFVFWNEtl6Ax8q31tWFnrQ6MEYs+H46PPDzeNzX1xLSFFe20sc6T46DKPaEGzAnt2CNUlYmFfQ== nwalsh21@LAPTOP-QQ65I1N1';

console.log(parseSSHRSAPublicKey(rawPublicKey));

const analyzer = new RSASignatureAnalyzer();
// const result = analyzer.analyzeRawSignature(rawSig);
const result = parseRSA_SHA2_512Signature(rawSig);
//console.log(result);
const defaults = generateDefaultPKCS1BigInts();
console.log(defaults);

const claimedMessage = analyzer.modPow(result.signatureBigInt, result.exponentBigInt, result.modulusBigInt);
console.log("New residue: ", claimedMessage);

// The below line is what will need to be proven in circom
assert(defaults.includes(claimedMessage));
//assert(result.signatureAnalysis.analysis.residueHex === analyzer.bigIntToBuffer(pkcs1Encoding, 512).toString('hex'));
//assert(pkcs1Encoding === result.signatureAnalysis.modularResidue.residueBigInt);

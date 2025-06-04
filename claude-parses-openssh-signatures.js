// RSA Signature Residue Extractor
// Extracts the modular residue from RSA signatures

const NodeRSA = require('node-rsa');
const crypto = require('crypto');

class RSASignatureAnalyzer {
  constructor() {
    this.textEncoder = new TextEncoder();
    this.textDecoder = new TextDecoder();
  }

  // Parse OpenSSH signature and extract the raw signature bytes
  parseOpenSSHSignature(base64Signature) {
    const binaryData = this.base64ToArrayBuffer(base64Signature);
    const view = new DataView(binaryData);
    let offset = 0;

    // Check for SSH signature magic bytes "SSHSIG"
    const magicBytes = new Uint8Array(binaryData, offset, 6);
    const magic = this.textDecoder.decode(magicBytes);
    if (magic !== 'SSHSIG') {
      throw new Error(`Expected SSHSIG magic bytes, got: ${magic}`);
    }
    offset += 6;

    // Parse signature version (4 bytes)
    const version = view.getUint32(offset, false);
    offset += 4;

    // Parse public key
    const publicKeyLength = view.getUint32(offset, false);
    offset += 4;
    const publicKeyData = new Uint8Array(binaryData, offset, publicKeyLength);
    offset += publicKeyLength;

    // Parse namespace
    const namespaceLength = view.getUint32(offset, false);
    offset += 4;
    const namespaceBytes = new Uint8Array(binaryData, offset, namespaceLength);
    const namespace = this.textDecoder.decode(namespaceBytes);
    offset += namespaceLength;

    // Skip reserved field (4 null bytes)
    offset += 4;

    // Parse hash algorithm
    const hashAlgoLength = view.getUint32(offset, false);
    offset += 4;
    const hashAlgoBytes = new Uint8Array(binaryData, offset, hashAlgoLength);
    const hashAlgorithm = this.textDecoder.decode(hashAlgoBytes);
    offset += hashAlgoLength;

    // Parse signature
    const signatureLength = view.getUint32(offset, false);
    offset += 4;
    const signatureData = new Uint8Array(binaryData, offset, signatureLength);

    // The signature data itself is a nested SSH wire format
    // Parse the inner signature format
    const sigView = new DataView(signatureData.buffer, signatureData.byteOffset);
    let sigOffset = 0;

    // Parse signature algorithm
    const sigAlgoLength = sigView.getUint32(sigOffset, false);
    sigOffset += 4;
    const sigAlgoBytes = new Uint8Array(signatureData.buffer, signatureData.byteOffset + sigOffset, sigAlgoLength);
    const signatureAlgorithm = this.textDecoder.decode(sigAlgoBytes);
    sigOffset += sigAlgoLength;

    if (!signatureAlgorithm.includes('rsa')) {
      throw new Error(`Expected RSA signature algorithm, got: ${signatureAlgorithm}`);
    }

    // Parse actual signature bytes
    const actualSigLength = sigView.getUint32(sigOffset, false);
    sigOffset += 4;
    const actualSignatureBytes = new Uint8Array(signatureData.buffer, signatureData.byteOffset + sigOffset, actualSigLength);

    return {
      magic: magic,
      version: version,
      publicKey: publicKeyData,
      namespace: namespace,
      hashAlgorithm: hashAlgorithm,
      signatureAlgorithm: signatureAlgorithm,
      signatureBytes: actualSignatureBytes
    };
  }

  // Extract RSA components from raw SSH public key bytes
  extractRSAComponents(publicKeyBytes) {
    // Parse the raw SSH public key format
    const view = new DataView(publicKeyBytes.buffer, publicKeyBytes.byteOffset);
    let offset = 0;

    // Parse key type
    const keyTypeLength = view.getUint32(offset, false);
    offset += 4;
    const keyTypeBytes = new Uint8Array(publicKeyBytes.buffer, publicKeyBytes.byteOffset + offset, keyTypeLength);
    const keyType = this.textDecoder.decode(keyTypeBytes);
    offset += keyTypeLength;

    if (keyType !== 'ssh-rsa') {
      throw new Error(`Expected ssh-rsa key type, got: ${keyType}`);
    }

    // Parse exponent (e)
    const exponentLength = view.getUint32(offset, false);
    offset += 4;
    const exponentBytes = new Uint8Array(publicKeyBytes.buffer, publicKeyBytes.byteOffset + offset, exponentLength);
    offset += exponentLength;

    // Parse modulus (n)
    const modulusLength = view.getUint32(offset, false);
    offset += 4;
    let modulusBytes = new Uint8Array(publicKeyBytes.buffer, publicKeyBytes.byteOffset + offset, modulusLength);

    // Remove leading zero byte if present (SSH wire format padding)
    if (modulusBytes.length > 0 && modulusBytes[0] === 0x00) {
      modulusBytes = modulusBytes.slice(1);
    }

    // Remove leading zero byte from exponent if present
    let cleanExponentBytes = exponentBytes;
    if (exponentBytes.length > 0 && exponentBytes[0] === 0x00) {
      cleanExponentBytes = exponentBytes.slice(1);
    }

    // Convert to expected format
    const modulusBuffer = Buffer.from(modulusBytes);
    const exponentBuffer = Buffer.from(cleanExponentBytes);
    
    // Convert exponent to number (it's usually 65537)
    let exponentNumber = 0;
    for (let i = 0; i < cleanExponentBytes.length; i++) {
      exponentNumber = (exponentNumber << 8) + cleanExponentBytes[i];
    }

    return {
      modulus: modulusBuffer,
      exponent: exponentNumber,
      modulusBigInt: this.bufferToBigInt(modulusBuffer),
      exponentBigInt: BigInt(exponentNumber)
    };
  }

  // Convert signature to modular residue: signature^e mod n
  extractModularResidue(signatureBytes, rsaComponents) {
    // Convert signature to BigInt
    const signatureBigInt = this.bufferToBigInt(Buffer.from(signatureBytes));
    
    // Perform modular exponentiation: s^e mod n
    const residue = this.modPow(signatureBigInt, rsaComponents.exponentBigInt, rsaComponents.modulusBigInt);
    
    return {
      residueBigInt: residue,
      residueHex: residue.toString(16),
      residueBuffer: this.bigIntToBuffer(residue, rsaComponents.modulus.length)
    };
  }

  // Analyze the residue structure (PKCS#1 v1.5 padding)
  analyzePKCS1Residue(residueBuffer) {
    const analysis = {
      raw: residueBuffer,
      hex: residueBuffer.toString('hex'),
      valid: false,
      paddingType: null,
      hashAlgorithm: null,
      hash: null
    };

    if (residueBuffer.length === 0) return analysis;

    // Check PKCS#1 v1.5 signature padding (00 01 FF...FF 00 ASN.1 HASH)
    if (residueBuffer[0] === 0x00 && residueBuffer[1] === 0x01) {
      analysis.paddingType = 'PKCS#1 v1.5';
      
      // Find the end of FF padding
      let i = 2;
      while (i < residueBuffer.length && residueBuffer[i] === 0xFF) {
        i++;
      }
      
      if (i < residueBuffer.length && residueBuffer[i] === 0x00) {
        analysis.valid = true;
        i++; // Skip the 00 separator
        
        // Parse ASN.1 DigestInfo structure
        const digestInfo = residueBuffer.slice(i);
        const hashInfo = this.parseDigestInfo(digestInfo);
        
        if (hashInfo) {
          analysis.hashAlgorithm = hashInfo.algorithm;
          analysis.hash = hashInfo.hash;
        }
      }
    }

    return analysis;
  }

  // Parse ASN.1 DigestInfo to extract hash algorithm and hash value
  parseDigestInfo(digestInfo) {
    // This is a simplified ASN.1 parser for common hash algorithms
    // In production, you'd want to use a proper ASN.1 library
    
    const commonPrefixes = {
      // SHA-1: 30 21 30 09 06 05 2b 0e 03 02 1a 05 00 04 14
      '300906052b0e03021a0500': { algorithm: 'SHA-1', hashLength: 20 },
      // SHA-256: 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20
      '300d06096086480165030402010500': { algorithm: 'SHA-256', hashLength: 32 },
      // SHA-384: 30 41 30 0d 06 09 60 86 48 01 65 03 04 02 02 05 00 04 30
      '300d06096086480165030402020500': { algorithm: 'SHA-384', hashLength: 48 },
      // SHA-512: 30 51 30 0d 06 09 60 86 48 01 65 03 04 02 03 05 00 04 40
      '300d06096086480165030402030500': { algorithm: 'SHA-512', hashLength: 64 }
    };

    const hexPrefix = digestInfo.slice(0, 30).toString('hex');
    
    for (const [prefix, info] of Object.entries(commonPrefixes)) {
      if (hexPrefix.includes(prefix)) {
        const hashStart = digestInfo.length - info.hashLength;
        const hash = digestInfo.slice(hashStart);
        
        return {
          algorithm: info.algorithm,
          hash: hash,
          hashHex: hash.toString('hex')
        };
      }
    }
    
    return null;
  }

  // Complete analysis of an OpenSSH signature
  analyzeSignature(opensshSignature) {
    // Parse signature
    const signatureInfo = this.parseOpenSSHSignature(opensshSignature);
    
    // Extract RSA components from the public key in the signature
    const rsaComponents = this.extractRSAComponents(signatureInfo.publicKey);
    
    // Extract modular residue
    const residueInfo = this.extractModularResidue(signatureInfo.signatureBytes, rsaComponents);
    
    // Analyze the residue structure
    const residueAnalysis = this.analyzePKCS1Residue(residueInfo.residueBuffer);
    
    return {
      signatureFormat: {
        magic: signatureInfo.magic,
        version: signatureInfo.version,
        publicKeyHex: Buffer.from(signatureInfo.publicKey).toString('hex'),
        namespace: signatureInfo.namespace,
        hashAlgorithm: signatureInfo.hashAlgorithm,
        signatureAlgorithm: signatureInfo.signatureAlgorithm
      },
      signature: {
        hex: Buffer.from(signatureInfo.signatureBytes).toString('hex'),
        length: signatureInfo.signatureBytes.length
      },
      rsaComponents: {
        modulusHex: rsaComponents.modulus.toString('hex'),
        modulusLength: rsaComponents.modulus.length,
        modulusBigInt: rsaComponents.modulusBigInt.toString(),
        exponent: rsaComponents.exponent
      },
      modularResidue: {
        hex: residueInfo.residueHex,
        length: residueInfo.residueBuffer.length,
        residueBigInt: residueInfo.residueBigInt.toString()
      },
      analysis: {
        valid: residueAnalysis.valid,
        paddingType: residueAnalysis.paddingType,
        hashAlgorithm: residueAnalysis.hashAlgorithm,
        hashHex: residueAnalysis.hash ? residueAnalysis.hash.toString('hex') : null,
        residueHex: residueAnalysis.hex
      }
    };
  }

  // Construct the SSH signature block that gets signed
  constructSSHSignatureBlock(message, namespace, hashAlgorithm, encoding = 'utf8') {
    // Convert message to buffer if it's a string
    const messageBuffer = typeof message === 'string' ? Buffer.from(message, encoding) : message;
    
    // Hash the message using the specified algorithm
    const nodeHashAlgo = this.mapHashAlgorithm(hashAlgorithm);
    const messageHash = crypto.createHash(nodeHashAlgo).update(messageBuffer).digest();
    
    // Construct the SSH signature block
    const parts = [];
    
    // 1. Magic bytes: "SSHSIG"
    parts.push(Buffer.from('SSHSIG', 'utf8'));
    
    // 2. Namespace field (length-prefixed)
    const namespaceBuffer = Buffer.from(namespace, 'utf8');
    const namespaceLengthBuffer = Buffer.allocUnsafe(4);
    namespaceLengthBuffer.writeUInt32BE(namespaceBuffer.length, 0);
    parts.push(namespaceLengthBuffer);
    parts.push(namespaceBuffer);
    
    // 3. Reserved field (4 null bytes)
    parts.push(Buffer.alloc(4, 0));
    
    // 4. Hash algorithm field (length-prefixed) - use Node.js format
    const hashAlgBuffer = Buffer.from(nodeHashAlgo, 'utf8');
    const hashAlgLengthBuffer = Buffer.allocUnsafe(4);
    hashAlgLengthBuffer.writeUInt32BE(hashAlgBuffer.length, 0);
    parts.push(hashAlgLengthBuffer);
    parts.push(hashAlgBuffer);
    
    // 5. Hash of message field (length-prefixed)
    const hashLengthBuffer = Buffer.allocUnsafe(4);
    hashLengthBuffer.writeUInt32BE(messageHash.length, 0);
    parts.push(hashLengthBuffer);
    parts.push(messageHash);
    
    return Buffer.concat(parts);
  }

  // Test multiple message variations to find the correct one
  findMatchingMessage(opensshSignature, baseMessage) {
    const variations = [
      { name: 'original', message: baseMessage },
      { name: 'with LF', message: baseMessage + '\n' },
      { name: 'with CRLF', message: baseMessage + '\r\n' },
      { name: 'without trailing newline', message: baseMessage.replace(/\n$/, '').replace(/\r\n$/, '') },
      { name: 'trimmed', message: baseMessage.trim() },
      { name: 'trimmed + LF', message: baseMessage.trim() + '\n' },
      { name: 'trimmed + CRLF', message: baseMessage.trim() + '\r\n' }
    ];

    const results = [];
    
    for (const variation of variations) {
      const result = this.verifyMessage(opensshSignature, variation.message);
      results.push({
        variation: variation.name,
        message: variation.message,
        messageHex: Buffer.from(variation.message).toString('hex'),
        valid: result.valid,
        computedHash: result.analysis ? result.analysis.computedHash : null
      });
      
      if (result.valid) {
        return {
          found: true,
          matchingVariation: variation.name,
          matchingMessage: variation.message,
          allResults: results
        };
      }
    }

    return {
      found: false,
      allResults: results
    };
  }

  // Verify if a message matches the signature
  verifyMessage(opensshSignature, message, encoding = 'utf8') {
    // Analyze the signature first
    const analysis = this.analyzeSignature(opensshSignature);
    
    if (!analysis.analysis.valid) {
      return {
        valid: false,
        reason: 'Invalid signature padding or format',
        debug: analysis.analysis
      };
    }

    if (!analysis.analysis.hashAlgorithm) {
      return {
        valid: false,
        reason: 'Could not determine hash algorithm from signature',
        debug: analysis.analysis
      };
    }

    // Get the namespace and hash algorithm from the signature
    const namespace = analysis.signatureFormat.namespace;
    const hashAlgorithm = analysis.analysis.hashAlgorithm;
    
    // Construct the SSH signature block
    const signatureBlock = this.constructSSHSignatureBlock(message, namespace, hashAlgorithm, encoding);
    
    // Hash the signature block using the algorithm found in the signature
    const nodeHashAlgo = this.mapHashAlgorithm(hashAlgorithm);
    const computedHash = crypto.createHash(nodeHashAlgo).update(signatureBlock).digest();
    
    // Compare with the hash from the signature
    const signatureHash = analysis.analysis.hashHex;
    const computedHashHex = computedHash.toString('hex');

    const matches = signatureHash === computedHashHex;

    return {
      valid: matches,
      reason: matches ? 'Message hash matches signature' : 'Message hash does not match signature',
      analysis: {
        hashAlgorithm: hashAlgorithm,
        nodeHashAlgorithm: nodeHashAlgo,
        namespace: namespace,
        expectedHash: signatureHash,
        computedHash: computedHashHex,
        message: typeof message === 'string' ? message : '[Buffer]',
        messageHex: (typeof message === 'string' ? Buffer.from(message, encoding) : message).toString('hex'),
        signatureBlockHex: signatureBlock.toString('hex'),
        signatureBlockLength: signatureBlock.length
      },
      debug: {
        fullSignatureAnalysis: analysis.analysis,
        residueHex: analysis.analysis.residueHex,
        paddingValid: analysis.analysis.valid
      }
    };
  }

  // Map signature hash algorithm names to Node.js crypto hash names
  mapHashAlgorithm(signatureHashAlgo) {
    const mapping = {
      'SHA-1': 'sha1',
      'SHA-256': 'sha256',
      'SHA-384': 'sha384',
      'SHA-512': 'sha512'
    };

    return mapping[signatureHashAlgo] || signatureHashAlgo.toLowerCase();
  }
  base64ToArrayBuffer(base64) {
    const buffer = Buffer.from(base64, 'base64');
    return buffer.buffer.slice(buffer.byteOffset, buffer.byteOffset + buffer.byteLength);
  }

  bufferToBigInt(buffer) {
    let result = 0n;
    for (let i = 0; i < buffer.length; i++) {
      result = (result << 8n) + BigInt(buffer[i]);
    }
    return result;
  }

  bigIntToBuffer(bigint, length) {
    const hex = bigint.toString(16).padStart(length * 2, '0');
    return Buffer.from(hex, 'hex');
  }

  modPow(base, exponent, modulus) {
    let result = 1n;
    base = base % modulus;
    
    while (exponent > 0n) {
      if (exponent % 2n === 1n) {
        result = (result * base) % modulus;
      }
      exponent = exponent >> 1n;
      base = (base * base) % modulus;
    }
    
    return result;
  }
}

// Example usage
const analyzer = new RSASignatureAnalyzer();

// Example (replace with actual values)
const opensshSignature = "U1NIU0lHAAAAAQAAAhcAAAAHc3NoLXJzYQAAAAMBAAEAAAIBALiE08Ltl3Rz5Irk/auYYW5oyfPKrtfgorcMj/+meP4F8cqsnbWZN6P3hXgAmkEowUo/3h8QJRj1Ld5K3X8LQj8UbjhurxdnYW7BkZP14h/KTY5T4FJi8GbEJUC8dCQ2ijnlmz2K/EVE7GzJ9S06PsI6aPatxfRsstPdlhnnLrYJEe7P0jbmOB4rsT3WgJRl3INFC3pKdR65u1dGftRVZVIuU9mH9BmwxPc4GuRVdN3XoFv8jLIvnET6hmo59r+13LeLDeYGDsVKGoh2JwwfoRjJzb99+AAykE11ETi97aPxAj0VqRu4T35LrgprYOF1kRkwLgUgICSZ81LTQET5dSPSmJax+XFTiXCAvPSJ4EJbXNe//MuHUedKzhjyorViCIPRj9WX+HpkGHakF3Xfq7T6q/MQh9NABEZVUUlZAVnJCVZlcf3zK+kRLb+S1AJVigHB6f2PaWR7BEiRJXyP0BxbAHxM/LjEqacbi5gspUbh0K/p6/dDy/BvxOTE2P2LwnwkAnq/O+V6J5X91L7s2oExlUUowsQyKDEp4e96iWZo71ufQF+K19373vFm9Rni+4CSUGeXc7fwcV2XE5GvKoc7NTS2ly9IPq+LbNRlb7ffdVHbEcUy//HIcod07bhhOG9MyfgAkwgGnLREm/hWxNK2b0ra4b3x6rU64FdXoZGLAAAAEGRvdWJsZS1ibGluZC54eXoAAAAAAAAABnNoYTUxMgAAAhQAAAAMcnNhLXNoYTItNTEyAAACAHZMWfhAgL46al9AgXoZN7Ug9IP4ifP7+bs92sPKjucnUXNpLPsu6zKPkwu1F75HM+M6S1MiJvFC0WFbc6jNIVV+GRa/ok5sqMFwSqxmEHEJDLXRvQWGqgDbiPpznnvSKpq+46UYD9uqFm3+qwrr4a4iad5kVj8y3mrYbx3LTf6yBLpqXAe6GMkDaIpiJtQy6VYeSi/LlNMnHJAc6hnwdt5heITDbgqfrRKHYWKMTM5ov0GsQBliHsxtD6169pw8/hqtrMLB8zeOSPUozFXJdnXrfdFJCMC+8z8NlbdmAG+D1huxTFVaA6Rl9u3TBx3H7km+FasO07j6kMLMsnXSSSrjWWNE8x3bAHEtA2LrzVzZdNmetyAwaBGRuX7twWa3OFpx27h9DLbU0WNiCCJZLqFyfxjqsgbFwSUE2c2ciRf4ieV8lk5rrUhcgf6ycfexKKQV+PujvpJ+3MzBlKbCbo48DsERiAM4mtTcWOAYl4tlY8W5ahtlGDfSvQbucw6FwCWumrvPFscyAQ/CKN1XJ5segzA1U4O4Rdbnt4IEW/vei2Fi21eNiR55J5peUthAaLqbr6JRBKEVg+KmPpxk5rL0ryZ9LK6WBBt36sE0yOIF3RonErbqt2zuQdWm4/rXVYS7qxrhNR527AMSOzvwHYaRLB2tnjkAMjgc2Ypcb76r"; // Your base64 signature

// Analyze signature
// const analysis = analyzer.analyzeSignature(opensshSignature);
// console.log('Complete analysis:', JSON.stringify(analysis, null, 2));

// Verify a message against the signature
const message = "E PLURIBUS UNUM; DO NOT SHARE";
//const verification = analyzer.verifyMessage(opensshSignature, message);
//console.log('Verification result:', JSON.stringify(verification, null, 2));

// Or try to find the correct message variation
const messageSearch = analyzer.findMatchingMessage(opensshSignature, message);
console.log('Message search result:', JSON.stringify(messageSearch, null, 2));

//console.log('RSA Signature Analyzer ready for use');

module.exports = RSASignatureAnalyzer;
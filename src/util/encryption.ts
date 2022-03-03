import crypto from "crypto";

import { ChaCha20Poly1305 } from "./chacha20poly1305";

export function verifyAndDecrypt(
  cipherText: Buffer,
  AAD: Buffer,
  nonce: Buffer,
  key: Buffer
): Buffer {
  const decryptor = new ChaCha20Poly1305(bufferToUint8Array(key));
  const result = decryptor.open(
    bufferToUint8Array(nonce),
    bufferToUint8Array(cipherText),
    AAD ? bufferToUint8Array(AAD) : undefined
  );

  if (!result) {
    throw new Error("Could not decrypt cipher");
  }
  return Buffer.from(result);
}

export function verifyAndDecrypt64(
  cipherText: Buffer,
  AAD: Buffer,
  nonce: Buffer,
  key: Buffer
): Buffer {
  const nonce64 = Buffer.alloc(12);
  nonce.copy(nonce64, 4);

  return verifyAndDecrypt(cipherText, AAD, nonce64, key);
}

export function encryptAndSeal(
  plainText: Buffer,
  AAD: Buffer,
  nonce: Buffer,
  key: Buffer
): Buffer {
  const encryptor = new ChaCha20Poly1305(key);
  return Buffer.from(
    encryptor.seal(
      bufferToUint8Array(nonce),
      bufferToUint8Array(plainText),
      AAD ? bufferToUint8Array(AAD) : undefined
    )
  );
}

export function encryptAndSeal64(
  plainText: Buffer,
  AAD: Buffer,
  nonce: Buffer,
  key: Buffer
): Buffer {
  const nonce64 = Buffer.alloc(12);
  nonce.copy(nonce64, 4);

  return encryptAndSeal(plainText, AAD, nonce64, key);
}

export function bufferToUint8Array(buf?: Buffer): Uint8Array {
  if (!buf) {
    return new Uint8Array(0);
  }

  const ab = new Uint8Array(buf.length);
  for (let i = 0; i < buf.length; ++i) {
    ab[i] = buf[i];
  }
  return ab;
}

export function HKDF(
  hashAlg: string,
  salt: Buffer,
  ikm: Buffer,
  info: Buffer,
  size: number
): Buffer {
  // create the hash alg to see if it exists and get its length
  const hash = crypto.createHash(hashAlg);
  const hashLength = hash.digest().length;

  // now we compute the PRK
  let hmac = crypto.createHmac(hashAlg, salt);
  hmac.update(ikm);
  const prk = hmac.digest();

  let output: Buffer;
  let prev = Buffer.alloc(0);
  const buffers: Buffer[] = [];
  const num_blocks = Math.ceil(size / hashLength);
  info = Buffer.from(info);

  for (let i = 0; i < num_blocks; i++) {
    hmac = crypto.createHmac(hashAlg, prk);

    const input = Buffer.concat([
      prev,
      info,
      Buffer.from(String.fromCharCode(i + 1)),
    ]);
    hmac.update(input);
    prev = hmac.digest();
    buffers.push(prev);
  }
  output = Buffer.concat(buffers, size);
  return output.slice(0, size);
}

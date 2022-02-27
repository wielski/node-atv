import { AEAD } from "@stablelib/aead";
import { streamXOR, stream } from "@stablelib/chacha";
import { Poly1305 } from "@stablelib/poly1305";
import { wipe } from "@stablelib/wipe";
import { writeUint64LE } from "@stablelib/binary";
import { equal } from "@stablelib/constant-time";

export const KEY_LENGTH = 32;
export const NONCE_LENGTH = 12;
export const TAG_LENGTH = 16;

const ZEROS = new Uint8Array(16);

export class ChaCha20Poly1305 implements AEAD {
  readonly nonceLength = NONCE_LENGTH;
  readonly tagLength = TAG_LENGTH;

  private _key: Uint8Array;

  constructor(key: Uint8Array) {
    if (key.length !== KEY_LENGTH) {
      throw new Error("ChaCha20Poly1305 needs 32-byte key");
    }
    this._key = new Uint8Array(key);
  }

  seal(
    nonce: Uint8Array,
    plaintext: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array
  ): Uint8Array {
    if (nonce.length > 16) {
      throw new Error("ChaCha20Poly1305: incorrect nonce length");
    }

    const counter = new Uint8Array(16);
    counter.set(nonce, counter.length - nonce.length);

    const authKey = new Uint8Array(32);
    stream(this._key, counter, authKey, 4);

    const resultLength = plaintext.length + this.tagLength;
    let result;
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error("ChaCha20Poly1305: incorrect destination length");
      }
      result = dst;
    } else {
      result = new Uint8Array(resultLength);
    }

    streamXOR(this._key, counter, plaintext, result, 4);

    this._authenticate(
      result.subarray(result.length - this.tagLength, result.length),
      authKey,
      result.subarray(0, result.length - this.tagLength),
      associatedData
    );

    wipe(counter);

    return result;
  }

  open(
    nonce: Uint8Array,
    sealed: Uint8Array,
    associatedData?: Uint8Array,
    dst?: Uint8Array
  ): Uint8Array | null {
    if (nonce.length > 16) {
      throw new Error("ChaCha20Poly1305: incorrect nonce length");
    }

    if (sealed.length < this.tagLength) {
      return null;
    }

    const counter = new Uint8Array(16);
    counter.set(nonce, counter.length - nonce.length);

    const authKey = new Uint8Array(32);
    stream(this._key, counter, authKey, 4);

    const calculatedTag = new Uint8Array(this.tagLength);
    this._authenticate(
      calculatedTag,
      authKey,
      sealed.subarray(0, sealed.length - this.tagLength),
      associatedData
    );

    if (
      !equal(
        calculatedTag,
        sealed.subarray(sealed.length - this.tagLength, sealed.length)
      )
    ) {
      return null;
    }

    const resultLength = sealed.length - this.tagLength;
    let result;
    if (dst) {
      if (dst.length !== resultLength) {
        throw new Error("ChaCha20Poly1305: incorrect destination length");
      }
      result = dst;
    } else {
      result = new Uint8Array(resultLength);
    }

    streamXOR(
      this._key,
      counter,
      sealed.subarray(0, sealed.length - this.tagLength),
      result,
      4
    );

    wipe(counter);

    return result;
  }

  clean(): this {
    wipe(this._key);
    return this;
  }

  // chacha20poly1305 RFC: [ AAD, AAD.length, CipherText, CipherText.length ]
  // lockdown format:      [ AAD, CipherText, AAD.length, CipherText.length ]
  private _authenticate(
    tagOut: Uint8Array,
    authKey: Uint8Array,
    ciphertext: Uint8Array,
    associatedData?: Uint8Array
  ) {
    const h = new Poly1305(authKey);

    if (associatedData) {
      h.update(associatedData);
      if (associatedData.length % 16 > 0) {
        h.update(ZEROS.subarray(associatedData.length % 16));
      }
    }

    h.update(ciphertext);
    if (ciphertext.length % 16 > 0) {
      h.update(ZEROS.subarray(ciphertext.length % 16));
    }

    const length = new Uint8Array(8);
    if (associatedData) {
      writeUint64LE(associatedData.length, length);
    }
    h.update(length);

    writeUint64LE(ciphertext.length, length);
    h.update(length);

    const tag = h.digest();
    for (let i = 0; i < tag.length; i++) {
      tagOut[i] = tag[i];
    }

    h.clean();
    wipe(tag);
    wipe(length);
  }
}

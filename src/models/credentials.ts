// import curve25519 from "curve25519-n2";
import encryption from "../util/encryption";
import number from "../util/number";

export class Credentials {
  public readKey: Buffer;
  public writeKey: Buffer;

  private encryptCount: number = 0;
  private decryptCount: number = 0;

  constructor(
    public identifier: Buffer,
    public pairingId: string,
    public publicKey: Buffer,
    public encryptionKey: Buffer
  ) {
    // const verifyPrivate = Buffer.alloc(32);
    // curve25519.makeSecretKey(verifyPrivate);

    // // let verifyPublic = curve25519.derivePublicKey(verifyPrivate);
    // let sharedSecret = curve25519.deriveSharedSecret(
    //   verifyPrivate,
    //   this.publicKey
    // );

    this.readKey = encryption.HKDF(
      "sha512",
      Buffer.from("ReadKeySaltMDLD"),
      this.publicKey,
      Buffer.from("ReadKeyInfoMDLD"),
      32
    );

    this.writeKey = encryption.HKDF(
      "sha512",
      Buffer.from("WriteKeySaltMDLD"),
      this.publicKey,
      Buffer.from("WriteKeyInfoMDLD"),
      32
    );
  }

  static fromString(text: string): Credentials {
    let parts = text.split(":");
    return new Credentials(
      Buffer.from(parts[0], "hex"),
      Buffer.from(parts[1], "hex").toString(),
      Buffer.from(parts[2], "hex"),
      Buffer.from(parts[3], "hex")
    );
  }

  toString(): string {
    return (
      this.identifier.toString("hex") +
      ":" +
      Buffer.from(this.pairingId).toString("hex") +
      ":" +
      this.publicKey.toString("hex") +
      ":" +
      this.encryptionKey.toString("hex")
    );
  }

  encrypt(message: Buffer): {
    nonce: Buffer;
    payload: Buffer;
  } {
    let nonce = number.UInt53toBufferLE(this.encryptCount++);

    return {
      nonce,
      payload: Buffer.concat(
        encryption.encryptAndSeal(message, null, nonce, this.writeKey)
      ),
    };
  }

  decrypt(message: Buffer): Buffer {
    let nonce = number.UInt53toBufferLE(this.decryptCount++);
    let cipherText = message.slice(0, -16);
    let hmac = message.slice(-16);

    return encryption.verifyAndDecrypt(
      cipherText,
      hmac,
      null,
      nonce,
      this.readKey
    );
  }
}

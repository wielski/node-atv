import crypto from "crypto";
import encryption from "../util/encryption";
// import number from "../util/number";

export class Credentials {
  public readKey: Buffer;
  public writeKey: Buffer;

  // private encryptCount: number = 0;
  // private decryptCount: number = 0;

  constructor(
    public identifier: Buffer,
    public pairingId: string,
    public publicKey: Buffer,
    public encryptionKey: Buffer,
    public sharedKey: Buffer // TODO: rm?
  ) {
    this.readKey = encryption.HKDF(
      "sha512",
      Buffer.from("ReadKeySaltMDLD"),
      this.sharedKey,
      Buffer.from("ReadKeyInfoMDLD"),
      32
    );

    this.writeKey = encryption.HKDF(
      "sha512",
      Buffer.from("WriteKeySaltMDLD"),
      this.sharedKey,
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
      Buffer.from(parts[3], "hex"),
      Buffer.from(parts[4], "hex") // TODO: rm?
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
      this.encryptionKey.toString("hex") +
      ":" +
      this.sharedKey.toString("hex") // TODO: rm?
    );
  }

  encrypt(message: Buffer): {
    nonce: Buffer;
    payload: Buffer;
  } {
    let nonce = crypto.randomBytes(12);

    return {
      nonce,
      payload: encryption.encryptAndSeal(message, null, nonce, this.writeKey),
    };
  }

  decrypt(message: Buffer, nonce: Buffer): Buffer {
    let cipherText = message.slice(0, -16);
    let hmac = message.slice(-16);

    return encryption.verifyAndDecrypt(cipherText, hmac, nonce, this.readKey);
  }
}

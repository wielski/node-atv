import BufferSerializer from "buffer-serializer";
import { UsbmuxdPairRecord } from "../clients/usbmuxd";

interface CredentialsModel {
  identifier: Buffer;
  pairingId: string;
  publicKey: Buffer;
  systemBuid: string;
  EscrowBag: Buffer;
  UDID: string;
  wifiMac: string;
  pairingRecord: UsbmuxdPairRecord;
}

export class Credentials {
  constructor(private credentials: CredentialsModel) {}

  get pairingRecord() {
    return this.credentials.pairingRecord;
  }

  get wifiMac() {
    return this.credentials.wifiMac;
  }

  get UDID() {
    return this.credentials.UDID;
  }

  static fromString(text: string): Credentials {
    const serializer = new BufferSerializer();
    const parsed = serializer.fromBuffer(Buffer.from(text, "hex"));
    return new Credentials({
      identifier: parsed.identifier,
      pairingId: parsed.pairingId,
      publicKey: parsed.publicKey,
      systemBuid: parsed.systemBuid,
      EscrowBag: parsed.EscrowBag,
      UDID: parsed.UDID,
      wifiMac: parsed.wifiMac,
      pairingRecord: parsed.pairingRecord,
    });
  }

  toString(): string {
    const serializer = new BufferSerializer();
    return serializer.toBuffer(this.credentials).toString("hex");
  }
}

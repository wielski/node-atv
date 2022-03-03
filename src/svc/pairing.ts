import { SRP, SrpClient } from "fast-srp-hap";
import crypto from "crypto";
import ed25519 from "ed25519";
import { v4 as uuidv4 } from "uuid";
import getmac from "getmac";

import { Credentials } from "../models/credentials";
import { LockdowndClient } from "../clients/lockdownd";

import { verifyAndDecrypt64, encryptAndSeal64, HKDF } from "../util/encryption";
import { opack_pack } from "../util/opack";
import tlv from "../util/tlv";
import { UsbmuxdClient } from "../clients/usbmuxd";

export type PairPinResponse = (pin: string) => Promise<Credentials>;

interface SrpPayload {
  srp: SrpClient;
  publicKey: Buffer;
  proof: Buffer;
}

export class Pairing {
  private key: Buffer = crypto.randomBytes(32);

  constructor(
    private lockdownd: LockdowndClient,
    private usbmuxd: UsbmuxdClient
  ) {}

  async initiatePair(): Promise<PairPinResponse> {
    const tlvData = tlv.encode(
      tlv.Tag.PairingMethod,
      0x00,
      tlv.Tag.Sequence,
      0x01
    );

    let message = await this.lockdownd.initiatePairing(tlvData);
    let pairingData = message.Payload;
    let decodedData = tlv.decode(pairingData);

    if (decodedData[tlv.Tag.BackOff]) {
      let backOff: Buffer = decodedData[tlv.Tag.BackOff];
      let miliseconds = backOff.readIntBE(0, backOff.byteLength);
      if (miliseconds > 0) {
        throw new Error(
          `You've attempt to pair too recently. Try again in ${
            miliseconds / 1000
          } seconds.`
        );
      }
    }

    if (decodedData[tlv.Tag.ErrorCode]) {
      let buffer: Buffer = decodedData[tlv.Tag.ErrorCode];
      const code = buffer.readIntBE(0, buffer.byteLength);
      throw new Error(
        `Device responded with error code ${code}. Try rebooting your Apple TV.`
      );
    }

    const deviceSalt = decodedData[tlv.Tag.Salt];
    const devicePublicKey = decodedData[tlv.Tag.PublicKey];

    if (deviceSalt.byteLength != 16) {
      throw new Error(
        `salt must be 16 bytes (but was ${deviceSalt.byteLength})`
      );
    }

    if (devicePublicKey.byteLength !== 384) {
      throw new Error(
        `serverPublicKey must be 384 bytes (but was ${devicePublicKey.byteLength})`
      );
    }

    return async (pin: string) => {
      return await this.completePairing(pin, deviceSalt, devicePublicKey);
    };
  }

  private async completePairing(
    pin: string,
    deviceSalt: Buffer,
    devicePublicKey: Buffer
  ): Promise<Credentials> {
    const srpPayload = this.createSrpPayload(pin, deviceSalt, devicePublicKey);

    const message = await this.sendPinSequence(srpPayload);
    let pairingData = tlv.decode(message.Payload);

    if (pairingData[tlv.Tag.ErrorCode]) {
      throw new Error(
        `Pin pairing returned error code: ${pairingData[
          tlv.Tag.ErrorCode
        ].toString()}`
      );
    }

    // FIXME: M2 check
    // const deviceProof = tlv.decode(pairingData)[tlv.Tag.Proof];
    // srpPayload.srp.checkM2(deviceProof);

    let seed = crypto.randomBytes(32);
    let keyPair = ed25519.MakeKeypair(seed);
    let privateKey = keyPair.privateKey;
    let publicKey = keyPair.publicKey;
    let sharedSecret = srpPayload.srp.computeK();

    let deviceHash = HKDF(
      "sha512",
      Buffer.from("Pair-Setup-Controller-Sign-Salt"),
      sharedSecret,
      Buffer.from("Pair-Setup-Controller-Sign-Info"),
      32
    );

    let pairingId = uuidv4();
    let deviceInfo = Buffer.concat([
      deviceHash,
      Buffer.from(pairingId),
      publicKey,
    ]);

    let deviceSignature = ed25519.Sign(deviceInfo, privateKey);
    let encryptionKey = HKDF(
      "sha512",
      Buffer.from("Pair-Setup-Encrypt-Salt"),
      sharedSecret,
      Buffer.from("Pair-Setup-Encrypt-Info"),
      32
    );

    const macAddress = getmac().split(":");
    const macAddressBuf = Buffer.alloc(macAddress.length);

    for (let i = 0; i < macAddress.length; i++) {
      const tmpByte = parseInt(macAddress[i], 16);
      macAddressBuf.writeUInt8(tmpByte, i);
    }

    const additionalData = {
      accountID: pairingId,
      model: "HackbookPro13,37",
      name: "Node-ATV",
      mac: macAddressBuf,
    };

    const ssrMessage = await this.sendSsrSequence(
      pairingId,
      publicKey,
      deviceSignature,
      encryptionKey,
      additionalData
    );

    if (ssrMessage.doSRPPair !== "succeed") {
      throw new Error(`SSR pairing ${pairingId} not being successed`);
    }

    let encryptedData = tlv.decode(ssrMessage.Payload)[tlv.Tag.EncryptedData];
    let decrpytedData = verifyAndDecrypt64(
      encryptedData,
      null,
      Buffer.from("PS-Msg06"),
      encryptionKey
    );
    let tlvData = tlv.decode(decrpytedData);

    return this.pairingCu(tlvData[tlv.Tag.Username], pairingId, sharedSecret);
  }

  private async pairingCu(
    identifier: Buffer,
    pairingId: string,
    sharedSecret: Buffer
  ): Promise<Credentials> {
    const wifiMac = await this.lockdownd.getValueCU<string>(
      "WiFiAddress",
      sharedSecret
    );
    const publicKey = await this.lockdownd.getValueCU<Buffer>(
      "DevicePublicKey",
      sharedSecret
    );

    const systemBuid = uuidv4();
    const pairingRecord = this.usbmuxd.getPairingRecord(
      publicKey.toString(),
      systemBuid,
      pairingId
    );

    const { EscrowBag, UDID } = await this.lockdownd.pairCU(
      {
        DeviceCertificate: pairingRecord.DeviceCertificate,
        HostCertificate: pairingRecord.HostCertificate,
        HostID: pairingRecord.HostID,
        RootCertificate: pairingRecord.RootCertificate,
        SystemBUID: pairingRecord.SystemBUID,
      },
      sharedSecret
    );

    return new Credentials({
      identifier,
      pairingId,
      publicKey,
      systemBuid,
      EscrowBag,
      UDID,
      wifiMac,
      pairingRecord,
    });
  }

  private async sendPinSequence(srpPayload: SrpPayload) {
    let tlvData = tlv.encode(
      tlv.Tag.Sequence,
      0x03,
      tlv.Tag.PublicKey,
      srpPayload.publicKey,
      tlv.Tag.Proof,
      srpPayload.proof
    );

    return await this.lockdownd.pinPairing(tlvData);
  }

  private async sendSsrSequence(
    pairingId: string,
    publicKey: Buffer,
    signature: Buffer,
    encryptionKey: Buffer,
    additionalData?: Record<string, unknown>
  ) {
    const tlvArgs = [
      tlv.Tag.PublicKey,
      publicKey,
      tlv.Tag.Signature,
      signature,
      tlv.Tag.Permissions,
      opack_pack({
        "com.apple.ScreenCapture": true,
        "com.apple.developer": true,
      }),
    ];

    let tlvData = tlv.encode(
      tlv.Tag.Username,
      Buffer.from(pairingId),
      ...tlvArgs
    );

    if (additionalData) {
      tlvData = tlv.encode(
        tlv.Tag.Username,
        Buffer.from(pairingId),
        tlv.Tag.Additional,
        opack_pack(additionalData),
        ...tlvArgs
      );
    }

    let encryptedTLV = encryptAndSeal64(
      tlvData,
      null,
      Buffer.from("PS-Msg05"),
      encryptionKey
    );

    let outerTLV = tlv.encode(
      tlv.Tag.Sequence,
      0x05,
      tlv.Tag.EncryptedData,
      encryptedTLV
    );

    return await this.lockdownd.ssrPairing(outerTLV);
  }

  private createSrpPayload(
    pin: string,
    deviceSalt: Buffer,
    devicePublicKey: Buffer
  ): SrpPayload {
    const srp = new SrpClient(
      SRP.params.hap,
      deviceSalt,
      Buffer.from("Pair-Setup"),
      Buffer.from(pin),
      this.key
    );
    srp.setB(devicePublicKey);

    const publicKey = srp.computeA();
    const proof = srp.computeM1();

    return {
      srp,
      publicKey,
      proof,
    };
  }
}

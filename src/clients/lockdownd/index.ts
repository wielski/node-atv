import type net from "net";
import bplistCreate from "bplist-creator";
import bplistParser from "bplist-parser";
import crypto from "crypto";
import tls from "tls";

import { LockdownProtocolClient } from "../../protocols/lockdown";
import { ResponseError, ServiceClient } from "../client";
import type { UsbmuxdPairRecord } from "../usbmuxd";
import { HKDF, verifyAndDecrypt, encryptAndSeal } from "../../util/encryption";

import { DeviceValue, responseValidators } from "./types";

const defaultPlistData = {
  Label: "Xcode",
  ProtocolVersion: "2",
};

export class LockdowndClient extends ServiceClient<LockdownProtocolClient> {
  private currentSessionId?: string;
  private defaultSocket?: net.Socket;

  constructor(public socket: net.Socket) {
    super(socket, new LockdownProtocolClient(socket));
  }

  async startService(name: string) {
    const resp = await this.protocolClient.sendMessage({
      Request: "StartService",
      Service: name,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndServiceResponse(resp)) {
      return { port: resp.Port, enableServiceSSL: !!resp.EnableServiceSSL };
    } else {
      throw new ResponseError(`Error starting service ${name}`, resp);
    }
  }

  async startSession(pairRecord: UsbmuxdPairRecord): Promise<void> {
    const resp = await this.protocolClient.sendMessage({
      Request: "StartSession",
      HostID: pairRecord.HostID,
      SystemBUID: pairRecord.SystemBUID,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndSessionResponse(resp)) {
      if (resp.EnableSessionSSL) {
        const ciphers = [
          "tls_aes_256_gcm_sha384",
          "tls_chacha20_poly1305_sha256",
          "tls_aes_128_gcm_sha256",
          "ecdhe-ecdsa-aes256-gcm-sha384",
          "ecdhe-rsa-aes256-gcm-sha384",
          "dhe-rsa-aes256-gcm-sha384",
          "ecdhe-ecdsa-chacha20-poly1305",
          "ecdhe-rsa-chacha20-poly1305",
          "dhe-rsa-chacha20-poly1305",
          "ecdhe-ecdsa-aes128-gcm-sha256",
          "ecdhe-rsa-aes128-gcm-sha256",
          "dhe-rsa-aes128-gcm-sha256",
          "ecdhe-ecdsa-aes256-sha384",
          "ecdhe-rsa-aes256-sha384",
          "dhe-rsa-aes256-sha256",
          "ecdhe-ecdsa-aes128-sha256",
          "ecdhe-rsa-aes128-sha256",
          "dhe-rsa-aes128-sha256",
          "ecdhe-ecdsa-aes256-sha",
          "ecdhe-rsa-aes256-sha",
          "dhe-rsa-aes256-sha",
          "ecdhe-ecdsa-aes128-sha",
          "ecdhe-rsa-aes128-sha",
          "dhe-rsa-aes128-sha",
          "aes256-gcm-sha384",
          "aes128-gcm-sha256",
          "aes256-sha256",
          "aes128-sha256",
          "aes256-sha",
          "aes128-sha",
        ];

        return new Promise((resolve, reject) => {
            const tlsSocket = tls.connect({
              socket: this.protocolClient.socket,
              rejectUnauthorized: false,
              secureContext: tls.createSecureContext({
                ciphers: ciphers.map((c) => c.toUpperCase()).join(":"),
                ca: pairRecord.DeviceCertificate,
                cert: pairRecord.RootCertificate.toString(),
                key: pairRecord.RootPrivateKey.toString(),
                minVersion: "TLSv1",
                maxVersion: "TLSv1.3",
              }),
            });

            const rejectConnection = () => {
              reject(new Error("TLS socket rejected connection"));
            };

            tlsSocket.on("error", rejectConnection);
            tlsSocket.on("timeout", rejectConnection);
            tlsSocket.on("ready", () => {
              tlsSocket.removeAllListeners();
              this.defaultSocket = this.socket;
              this.currentSessionId = resp.SessionID;
              this.socket = tlsSocket;
              this.protocolClient.socket = tlsSocket;
              resolve();
            });
        });
      }
    } else {
      throw new ResponseError("Error starting session", resp);
    }
  }

  async stopSession() {
    if (!this.currentSessionId) return;

    await this.protocolClient.sendMessage({
      Request: "StopSession",
      SessionID: this.currentSessionId,
      ...defaultPlistData,
    });

    this.socket = this.defaultSocket;
    this.protocolClient.socket = this.defaultSocket;
    this.defaultSocket = undefined;
  }

  async getAllValues() {
    const resp = await this.protocolClient.sendMessage({ Request: "GetValue" });

    if (responseValidators.isLockdowndAllValuesResponse(resp)) {
      return resp.Value;
    } else {
      throw new ResponseError("Error getting lockdown value", resp);
    }
  }

  async getValue(val: DeviceValue) {
    const resp = await this.protocolClient.sendMessage({
      Request: "GetValue",
      Key: val,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndValueResponse(resp)) {
      return resp.Value;
    } else {
      throw new ResponseError("Error getting lockdown value", resp);
    }
  }

  async initiatePairing(tlv: Buffer) {
    const resp = await this.protocolClient.sendMessage({
      Request: "CUPairingCreate",
      Flags: "1",
      Payload: tlv,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndInitialPairingResponse(resp)) {
      return resp.ExtendedResponse;
    } else {
      throw new ResponseError("Error pairing", resp);
    }
  }

  async pinPairing(tlv: Buffer) {
    const resp = await this.protocolClient.sendMessage({
      Request: "CUPairingCreate",
      Flags: "0",
      Payload: tlv,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndPinPairingResponse(resp)) {
      return resp.ExtendedResponse;
    } else {
      throw new ResponseError("Error pairing", resp);
    }
  }

  async ssrPairing(tlv: Buffer) {
    const resp = await this.protocolClient.sendMessage({
      Request: "CUPairingCreate",
      Flags: "0",
      Payload: tlv,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndSsrPairingResponse(resp)) {
      return resp.ExtendedResponse;
    } else {
      throw new ResponseError("Error pairing", resp);
    }
  }

  async queryType() {
    const resp = await this.protocolClient.sendMessage({
      Request: "QueryType",
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndQueryTypeResponse(resp)) {
      return resp.Type;
    } else {
      throw new ResponseError("Error getting lockdown query type", resp);
    }
  }

  async doHandshake(pairRecord: UsbmuxdPairRecord) {
    await this.startSession(pairRecord);
  }

  async sendRequestCu<R>(
    name: string,
    request: Record<string, unknown>,
    secret: Buffer
  ): Promise<R> {
    const [writeKey, readKey] = this.getKeyPair(secret);
    const nonce = crypto.randomBytes(12);
    const requestBplist = Buffer.from(bplistCreate(request));
    const payload = encryptAndSeal(requestBplist, null, nonce, writeKey);

    const resp = await this.protocolClient.sendMessage({
      Request: name,
      Nonce: nonce,
      Payload: payload,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndCUResponse(resp, name)) {
      const responseBuf = verifyAndDecrypt(
        resp.Payload,
        null,
        resp.Nonce,
        readKey
      );
      const responsePlist = await bplistParser.parseFile<R>(responseBuf);
      return responsePlist[0];
    } else {
      throw new ResponseError("Error getting lockdown CU response", resp);
    }
  }

  async getValueCU<R>(val: DeviceValue, secret: Buffer): Promise<R> {
    const request = {
      Key: String(val),
    };
    const response = await this.sendRequestCu<{ Value: R }>(
      "GetValueCU",
      request,
      secret
    );
    return response.Value;
  }

  async pairCU(
    pairRecord: {
      DeviceCertificate: Buffer;
      HostCertificate: Buffer;
      RootCertificate: Buffer;
      SystemBUID: string;
      HostID: string;
    },
    secret: Buffer
  ): Promise<{ EscrowBag: Buffer; UDID: string }> {
    const request = {
      PairRecord: pairRecord,
      PairingOptions: {
        ExtendedPairingErrors: true,
      },
    };

    return await this.sendRequestCu<{
      EscrowBag: Buffer;
      UDID: string;
    }>("PairCU", request, secret);
  }

  private getKeyPair(secret: Buffer) {
    const writeKey = HKDF(
      "sha512",
      Buffer.from("WriteKeySaltMDLD"),
      secret,
      Buffer.from("WriteKeyInfoMDLD"),
      32
    );

    const readKey = HKDF(
      "sha512",
      Buffer.from("ReadKeySaltMDLD"),
      secret,
      Buffer.from("ReadKeyInfoMDLD"),
      32
    );

    return [writeKey, readKey];
  }
}

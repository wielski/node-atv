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
      HostID: pairRecord.HostID.toUpperCase(),
      SystemBUID: pairRecord.SystemBUID,
      ...defaultPlistData,
    });

    if (responseValidators.isLockdowndSessionResponse(resp)) {
      if (resp.EnableSessionSSL) {
        return new Promise((resolve, reject) => {
          const tlsSocket = new tls.TLSSocket(
            this.protocolClient.socket,
            {
              secureOptions: crypto.constants.SSL_OP_NO_TLSv1_1,
              cert: pairRecord.RootCertificate,
              key: pairRecord.RootPrivateKey,
              // secureContext: tls.createSecureContext({
              //   // secureProtocol: "TLSv1_2_method",
              //   // ca: pairRecord.HostCertificate,
              //   cert: pairRecord.RootCertificate,
              //   key: pairRecord.RootPrivateKey,
              // }),
            }
          );

          const rejectSocket = () => {
            reject(new Error("TLS socket rejected connection"));
          };

          tlsSocket.on("close", rejectSocket);
          tlsSocket.on("timeout", rejectSocket);
          tlsSocket.on("ready", () => {
            this.currentSessionId = resp.SessionID;
            this.protocolClient.socket = tlsSocket;
            tlsSocket.removeAllListeners();
            resolve();
          });
        })
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

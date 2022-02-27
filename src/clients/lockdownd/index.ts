import type net from "net";
import plist from "plist";
import tls from "tls";
import { Credentials } from "../../models/credentials";

import { LockdownProtocolClient } from "../../protocols/lockdown";

import { ResponseError, ServiceClient } from "../client";
import type { UsbmuxdPairRecord } from "../usbmuxd";

import { DeviceValue, responseValidators } from "./types";

export class LockdowndClient extends ServiceClient<LockdownProtocolClient> {
  constructor(public socket: net.Socket) {
    super(socket, new LockdownProtocolClient(socket));
  }

  async startService(name: string) {
    const resp = await this.protocolClient.sendMessage({
      Request: "StartService",
      Service: name,
    });

    if (responseValidators.isLockdowndServiceResponse(resp)) {
      return { port: resp.Port, enableServiceSSL: !!resp.EnableServiceSSL };
    } else {
      throw new ResponseError(`Error starting service ${name}`, resp);
    }
  }

  async startSession(pairRecord: UsbmuxdPairRecord) {
    const resp = await this.protocolClient.sendMessage({
      Request: "StartSession",
      HostID: pairRecord.HostID,
      SystemBUID: pairRecord.SystemBUID,
    });

    if (responseValidators.isLockdowndSessionResponse(resp)) {
      if (resp.EnableSessionSSL) {
        this.protocolClient.socket = new tls.TLSSocket(
          this.protocolClient.socket,
          {
            secureContext: tls.createSecureContext({
              secureProtocol: "TLSv1_method",
              cert: pairRecord.RootCertificate,
              key: pairRecord.RootPrivateKey,
            }),
          }
        );
      }
    } else {
      throw new ResponseError("Error starting session", resp);
    }
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
    });

    if (responseValidators.isLockdowndValueResponse(resp)) {
      return resp.Value;
    } else {
      throw new ResponseError("Error getting lockdown value", resp);
    }
  }

  async getValueCU(val: DeviceValue, credentials: Credentials) {
    const request = {
      Key: val,
    };
    const { nonce, payload } = credentials.encrypt(
      Buffer.from(plist.build(request))
    );

    const resp = await this.protocolClient.sendMessage({
      Request: "GetValueCU",
      Nonce: nonce,
      Payload: payload,
      Label: "Xcode",
      ProtocolVersion: "2",
    });

    if (responseValidators.isLockdowndValueCUResponse(resp)) {
      return credentials.decrypt(resp.Payload, resp.Nonce);
    } else {
      throw new ResponseError("Error getting lockdown value", resp);
    }
  }

  async initiatePairing(tlv: Buffer) {
    const resp = await this.protocolClient.sendMessage({
      Request: "CUPairingCreate",
      Flags: "1",
      Payload: tlv,
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
}

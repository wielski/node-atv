import { pki } from "node-forge";
import net from "net";
import Bonjour from "bonjour";

import { LockdowndClient } from "../../clients/lockdownd";
import { Credentials } from "../../models/credentials";
import { sleepAsync } from "../../util/sleep";
import { dnsLookup } from "../../util/network";

export interface UsbmuxdPairRecord {
  DeviceCertificate: Buffer;
  HostCertificate: Buffer;
  HostID: string;
  HostPrivateKey: Buffer;
  RootCertificate: Buffer;
  RootPrivateKey: Buffer;
  SystemBUID: string;
}

export interface UsbmuxdGenericDevice {
  Host: string;
  Name: string;
  UDID?: string;
}

export type UsbmuxdPairableDevice = Omit<UsbmuxdGenericDevice, "UDID"> &
  Partial<Pick<UsbmuxdGenericDevice, "UDID">>;
export type UsbmuxdDevice = Omit<UsbmuxdGenericDevice, "UDID"> &
  Required<Pick<UsbmuxdGenericDevice, "UDID">>;

export class UsbmuxdClient {
  public async getDeviceList(
    credentials: Credentials
  ): Promise<UsbmuxdDevice[]> {
    return this.findDevices<UsbmuxdDevice>("apple-mobdev2", credentials);
  }

  public async getPairableDeviceList(): Promise<UsbmuxdPairableDevice[]> {
    return this.findDevices<UsbmuxdPairableDevice>("apple-pairable");
  }

  private async findDevices<T>(
    type: string,
    credentials?: Credentials
  ): Promise<T[]> {
    const bonjour = Bonjour();
    const services: Bonjour.RemoteService[] = [];

    const browser = bonjour.find(
      {
        type,
        protocol: "tcp",
      },
      (service: Bonjour.RemoteService) => {
        services.push(service);
      }
    );
    browser.start();
    browser.update();

    await sleepAsync(2000);

    bonjour.destroy();

    const serviceInfos = services.map((s) =>
      this.readServiceInfo(s, credentials)
    );
    const devices: T[] = await Promise.all(serviceInfos).catch(() => {
      return undefined;
    });

    return (devices || []).filter((d) => !!d);
  }

  public getPairingRecord(
    devicePublicKey: string,
    systemBuid: string,
    hostId: string,
    _udid?: string
  ): UsbmuxdPairRecord {
    const keySize = 2048;
    const rootKeyPair = pki.rsa.generateKeyPair(keySize);
    const hostKeyPair = pki.rsa.generateKeyPair(keySize);

    const rootCertificate = this.getCertificatePair([
      {
        name: "basicConstraints",
        critical: true,
        cA: true,
      },
      {
        name: 'subjectKeyIdentifier'
      },
    ], rootKeyPair.privateKey, rootKeyPair.publicKey);

    const hostCertificate = this.getCertificatePair([
      {
        name: "basicConstraints",
        critical: true,
        cA: false,
      },
      {
        name: 'subjectKeyIdentifier'
      },
      {
        name: "keyUsage",
        critical: true,
        digitalSignature: true,
        keyEncipherment: true,
        keyCertSign: false,
        nonRepudiation: false,
        dataEncipherment: false,
      },
    ], rootKeyPair.privateKey, hostKeyPair.publicKey);

    const deviceCertificate = this.getCertificatePair([
      {
        name: "basicConstraints",
        cA: false,
        critical: true,
      },
      {
        name: 'subjectKeyIdentifier'
      },
      {
        name: "keyUsage",
        critical: true,
        digitalSignature: true,
        keyEncipherment: true,
        keyCertSign: false,
        nonRepudiation: false,
        dataEncipherment: false,
      },
    ], rootKeyPair.privateKey, pki.publicKeyFromPem(devicePublicKey));

    const convertPrivateKeyToPem = (privateKey: pki.PrivateKey) => {
      const rsaPrivateKey = pki.privateKeyToAsn1(privateKey);
      const privateKeyInfo = pki.wrapRsaPrivateKey(rsaPrivateKey);
      return pki.privateKeyInfoToPem(privateKeyInfo);
    };

    return {
      DeviceCertificate: Buffer.from(
        pki.certificateToPem(deviceCertificate)
      ),
      HostPrivateKey: Buffer.from(
        convertPrivateKeyToPem(hostKeyPair.privateKey)
      ),
      HostCertificate: Buffer.from(
        pki.certificateToPem(hostCertificate)
      ),
      RootPrivateKey: Buffer.from(
        convertPrivateKeyToPem(rootKeyPair.privateKey)
      ),
      RootCertificate: Buffer.from(
        pki.certificateToPem(rootCertificate)
      ),
      SystemBUID: systemBuid.toUpperCase(),
      HostID: hostId.toUpperCase(),
    };
  }

  private async readServiceInfo(
    service: Bonjour.RemoteService,
    credentials?: Credentials
  ): Promise<UsbmuxdGenericDevice> {
    const deviceHost = await dnsLookup(service.host);
    const socket = net.createConnection({
      host: deviceHost,
      port: 62078,
    });
    const lockdownd = new LockdowndClient(socket);
    let UDID: string;

    if (
      credentials &&
      service.name &&
      service.name.indexOf(credentials.wifiMac) > -1
    ) {
      UDID = credentials.UDID;
    }

    try {
      const info = await lockdownd.getAllValues();

      return {
        Host: service.host,
        UDID: UDID,
        Name: info.DeviceName,
      };
    } catch (e) {
      return Promise.reject();
    }
  }

  private getCertificatePair(extensions: unknown[], privateKey: pki.PrivateKey, publicKey: pki.PublicKey, udid?: string) {
    const certificateAttrs = [];

    if (udid && udid.length > 0) {
      certificateAttrs.push({
        shortName: "CN",
        value: "Root Certification Authority",
      });
      certificateAttrs.push({
        shortName: "OU",
        value: udid,
      });
    }

    const notBefore = new Date();
    const notAfter = new Date(notBefore);
    notAfter.setDate(notAfter.getDate() + 365 * 10);

    const certificate = pki.createCertificate();
    certificate.publicKey = publicKey;
    certificate.version = 2;
    certificate.serialNumber = "00";
    certificate.validity.notBefore = notBefore;
    certificate.validity.notAfter = notAfter;
    certificate.setExtensions(extensions);
    certificate.setSubject(certificateAttrs);
    certificate.setIssuer(certificateAttrs);
    certificate.sign(privateKey);

    return certificate;
  }
}

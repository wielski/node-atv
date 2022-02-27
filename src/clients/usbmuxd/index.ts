import { pki } from "node-forge";
import { v4 as uuidv4 } from "uuid";
import net from "net";
import Bonjour from "bonjour";

import { LockdowndClient } from "../../clients/lockdownd";
import { sleepAsync } from "../../util/sleep";
import { Credentials } from "../../models/credentials";

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

export type UsbmuxdPairableDevice = Omit<UsbmuxdGenericDevice, "UDID"> & Partial<Pick<UsbmuxdGenericDevice, "UDID">>;
export type UsbmuxdDevice = Omit<UsbmuxdGenericDevice, "UDID"> & Required<Pick<UsbmuxdGenericDevice, "UDID">>;

export class UsbmuxdClient {
  get basicCaExtensions() {
    return [
      {
        name: "basicConstraints",
        cA: true,
      },
      {
        name: "subjectKeyIdentifier",
      },
    ];
  }

  get advancedCaExtensions() {
    return [
      {
        name: "keyUsage",
        keyCertSign: true,
        digitalSignature: true,
        nonRepudiation: true,
        keyEncipherment: true,
        dataEncipherment: true,
      },
    ];
  }

  public async getDeviceList(credentials: Credentials): Promise<UsbmuxdDevice[]> {
    return this.findDevices<UsbmuxdDevice>("apple-mobdev2", credentials);
  }

  public async getPairableDeviceList(): Promise<UsbmuxdPairableDevice[]> {
    return this.findDevices<UsbmuxdPairableDevice>("apple-pairable");
  }

  private async findDevices<T>(type: string, credentials?: Credentials): Promise<T[]> {
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

    const serviceInfos = services.map((s) => this.readServiceInfo(s, credentials));
    const devices: T[] = await Promise.all(serviceInfos).catch(() => {
      return undefined;
    });

    return (devices || []).filter((d) => !!d);
  }

  public getPairingRecord(
    devicePublicKey: string,
    udid?: string,
    systemBuid?: string
  ): UsbmuxdPairRecord {
    const rootCertificate = this.getCertificatePair(udid);
    const hostCertificate = this.getCertificatePair(udid);
    const deviceCertificate = this.getCertificatePair(udid, devicePublicKey);

    rootCertificate.certificate.setExtensions([...this.basicCaExtensions]);
    rootCertificate.certificate.sign(rootCertificate.keyPair.privateKey);

    hostCertificate.certificate.setExtensions([
      ...this.basicCaExtensions,
      ...this.advancedCaExtensions,
    ]);
    hostCertificate.certificate.sign(hostCertificate.keyPair.privateKey);

    deviceCertificate.certificate.setExtensions([
      ...this.basicCaExtensions,
      ...this.advancedCaExtensions,
    ]);

    const hostId: string = uuidv4();
    if (!systemBuid) {
      systemBuid = uuidv4();
    }

    return {
      DeviceCertificate: Buffer.from(
        pki.certificateToPem(deviceCertificate.certificate)
      ),
      HostPrivateKey: Buffer.from(
        pki.privateKeyToPem(hostCertificate.keyPair.privateKey)
      ),
      HostCertificate: Buffer.from(
        pki.certificateToPem(hostCertificate.certificate)
      ),
      RootPrivateKey: Buffer.from(
        pki.privateKeyToPem(rootCertificate.keyPair.privateKey)
      ),
      RootCertificate: Buffer.from(
        pki.certificateToPem(rootCertificate.certificate)
      ),
      SystemBUID: systemBuid.toUpperCase(),
      HostID: hostId.toUpperCase(),
    };
  }

  private async readServiceInfo(
    service: Bonjour.RemoteService,
    credentials?: Credentials,
  ): Promise<UsbmuxdGenericDevice> {
    const socket = net.createConnection({
      host: service.host,
      port: 62078,
      family: 4,
    });
    const lockdownd = new LockdowndClient(socket);

    // TODO: FIXME! get publicKey from lockdown DevicePublicKey???
    if (credentials) {
      try {
        const publicKey = await lockdownd.getValueCU("DevicePublicKey", credentials);
        console.log(publicKey);
        const pairRecord = this.getPairingRecord(publicKey.toString());
        await lockdownd.doHandshake(pairRecord);
      } catch (e) {
        console.log(e);
      }
    }

    try {
      const info = await lockdownd.getAllValues();

      return {
        Host: service.host,
        UDID: info.UniqueDeviceID,
        Name: info.DeviceName,
      };
    } catch(e) {
      return Promise.reject();
    }
  }

  private getCertificatePair(udid?: string, publicKey?: string) {
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

    let publicKeyFromPem: pki.PublicKey;
    if (publicKey) {
      publicKeyFromPem = pki.publicKeyFromPem(publicKey);
    }

    const keySize = 2048;
    const keyPair = pki.rsa.generateKeyPair(keySize);

    const certificate = pki.createCertificate();
    certificate.publicKey = publicKeyFromPem || keyPair.publicKey;
    certificate.serialNumber = "01";
    certificate.validity.notBefore = new Date();
    certificate.validity.notAfter = new Date();
    certificate.validity.notAfter.setFullYear(
      certificate.validity.notBefore.getFullYear() + 10
    );
    certificate.setSubject(certificateAttrs);
    certificate.setIssuer(certificateAttrs);

    return {
      keyPair,
      certificate,
    };
  }
}

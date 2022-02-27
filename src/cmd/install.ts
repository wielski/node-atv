import net from "net";

import { UsbmuxdClient, UsbmuxdDevice } from "../clients/usbmuxd";
import { LockdowndClient } from "../clients/lockdownd";
import { InstallationProxyClient } from "../clients/installer";
import { Credentials } from "../models/credentials";
import { AFCClient } from "../clients/afc";

import { InstallApp } from '../svc/installApp';

export async function main(credentials: Credentials, udid: string, ipaPath: string): Promise<string> {
  const usbmuxd = new UsbmuxdClient();
  const devices = await usbmuxd.getDeviceList(credentials);
  const device = devices.find((d) => d.UDID && d.UDID.replace(/\-/g, "") === udid.replace(/\-/g, ""));

  if (!device) {
    throw new Error(`Device with ${udid} not found in local network`);
  }

  return await install(credentials, device, ipaPath);
}

async function install(credentials: Credentials, device: UsbmuxdDevice, ipaPath: string): Promise<string> {
  const socket = net.createConnection({
    host: device.Host,
    port: 62078,
    family: 4,
  });

  const connection = new LockdowndClient(socket);
  const usbmuxd = new UsbmuxdClient();

  const pairRecord = usbmuxd.getPairingRecord(credentials.publicKey.toString(), device.UDID);
  await connection.doHandshake(pairRecord);

  const installer = new InstallationProxyClient(connection.socket);
  const afc = new AFCClient(connection.socket);

  const svc = new InstallApp(afc, installer);
  return svc.install(ipaPath);
}

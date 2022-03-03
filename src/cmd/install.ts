import net from "net";

import { UsbmuxdClient } from "../clients/usbmuxd";
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

  const socket = net.createConnection({
    host: device.Host,
    port: 62078,
    family: 4,
  });

  const lockdown = new LockdowndClient(socket);

  await lockdown.getValue("ProductVersion");
  await lockdown.getValue("ProductName");

  await lockdown.doHandshake(credentials.pairingRecord);

  let bundleId: string;

  try {
    await install(lockdown, ipaPath);
    lockdown.stopSession();
  } catch (e) {
    lockdown.stopSession();
    throw e;
  }

  return bundleId;
}

async function install(lockdown: LockdowndClient, ipaPath: string): Promise<string> {
  const installer = new InstallationProxyClient(lockdown.socket);
  const afc = new AFCClient(lockdown.socket);

  const svc = new InstallApp(afc, installer);

  console.log("Installing app...");
  return svc.install(ipaPath);
}

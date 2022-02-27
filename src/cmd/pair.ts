import net from "net";
import Readline from "readline";

import { UsbmuxdClient, UsbmuxdPairableDevice } from "../clients/usbmuxd";
import { LockdowndClient } from "../clients/lockdownd";
import { Pairing } from "../svc/pairing";
import { Credentials } from "../models/credentials";

const readline = Readline.createInterface({
  input: process.stdin,
  output: process.stdout,
});

export async function main(_udid: string, name: string): Promise<Credentials> {
  const usbmuxd = new UsbmuxdClient();
  const devices = await usbmuxd.getPairableDeviceList();
  const device = devices.find((d) => d.Name && d.Name.toLowerCase() === name.toLowerCase());

  if (!device) {
    throw new Error(`Device with name ${name} not found in local network`);
  }

  return await connect(device);
}

async function connect(device: UsbmuxdPairableDevice): Promise<Credentials> {
  const socket = net.createConnection({
    host: device.Host,
    port: 62078,
    family: 4,
  });
  const connection = new LockdowndClient(socket);
  const pairing = new Pairing(connection);

  console.log("Initiate pairing...");

  return new Promise((resolve, reject) => {
    pairing
      .initiatePair()
      .then((enterPin) => {
        console.log("Pin request");

        readline.question("Enter pin: ", (pin) => {
          enterPin(pin)
            .then((credentials) => {
              resolve(credentials);
            })
            .catch((e) => {
              reject(e);
            });
        });
      })
      .catch((e) => {
        reject(e);
      });
  });
}

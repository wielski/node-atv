import dns from "dns";
import { networkInterfaces, Systeminformation } from "systeminformation";

export function getNetworkInterface(): Promise<Systeminformation.NetworkInterfacesData> {
  return new Promise((resolve, reject) => {
    networkInterfaces((interfaces) => {
      const activeInterface = interfaces.find((iface) => !!iface["default"]);

      if (!activeInterface) {
        reject();
        return;
      }

      resolve(activeInterface);
    });
  });
}

export async function dnsLookup(
  host: string,
): Promise<string> {
  const networkInterface = await getNetworkInterface();
  const addressSuffix = `%${networkInterface.ifaceName}`;

  const ipv4 = await dnsLookupWithFamily(host, 4);
  const ipv6 = await dnsLookupWithFamily(host, 6);

  if (ipv6) {
    return `${ipv6}${addressSuffix}`;
  } else if (ipv4) {
    return ipv4;
  }

  throw new Error(`Could not resolve ip for ${host}`);
}

function dnsLookupWithFamily(host: string, family: 4 | 6): Promise<string> {
  return new Promise((resolve) => {
    dns.lookup(
      host,
      {
        family,
      },
      (err, address) => {
        if (err) {
          resolve(undefined);
        } else {
          resolve(address);
        }
      }
    );
  })
}

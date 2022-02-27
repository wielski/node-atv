import type net from "net";

import { LockdownProtocolClient } from "../../protocols/lockdown";
import { ResponseError, ServiceClient } from "../client";

import {
  IPMessage,
  IPOptions,
  IPInstallResponse,
  validateResponse,
} from "./types";

export class InstallationProxyClient extends ServiceClient<
  LockdownProtocolClient<IPMessage>
> {
  constructor(public socket: net.Socket) {
    super(socket, new LockdownProtocolClient(socket));
  }

  async lookupApp(
    bundleIds: string[],
    options: IPOptions = {
      ReturnAttributes: [
        "Path",
        "Container",
        "CFBundleExecutable",
        "CFBundleIdentifier",
      ],
      ApplicationsType: "Any",
    }
  ) {
    const resp = await this.protocolClient.sendMessage({
      Command: "Lookup",
      ClientOptions: {
        BundleIDs: bundleIds,
        ...options,
      },
    });
    if (validateResponse.isIPLookupResponse(resp)) {
      return resp[0].LookupResult;
    } else {
      throw new ResponseError(`There was an error looking up app`, resp);
    }
  }

  async installApp(
    packagePath: string,
    bundleId: string,
    options: IPOptions = {
      ApplicationsType: "Any",
      PackageType: "Developer",
    },
    callback?: (status: IPInstallResponse) => void
  ) {
    return this.protocolClient.sendMessage(
      {
        Command: "Install",
        PackagePath: packagePath,
        ClientOptions: {
          CFBundleIdentifier: bundleId,
          ...options,
        },
      },
      (resp: any, resolve, reject) => {
        if (validateResponse.isIPInstallCompleteResponse(resp)) {
          resolve();
        } else if (validateResponse.isIPInstallPercentCompleteResponse(resp)) {
          callback && callback(resp);
        } else if (
          validateResponse.isIPInstallCFBundleIdentifierResponse(resp)
        ) {
          callback && callback(resp);
        } else {
          reject(new ResponseError("There was an error installing app", resp));
        }
      }
    );
  }
}

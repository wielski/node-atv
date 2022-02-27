import fs from 'fs';
import os from 'os';
import path from "path";
import plist from "plist";
import glob from "glob";
import extract from "extract-zip";

import { InstallationProxyClient } from "../clients/installer";

import { AFCClient } from "../clients/afc";
import { AFCError } from "../protocols/afc";
import { AFCStatus } from "../protocols/afc/consts";

export class InstallApp {
  constructor(
    private afc: AFCClient,
    private installer: InstallationProxyClient,
  ) {}

  async install(appPath: string): Promise<string> {
    const packageName = path.basename(appPath);
    const destPackagePath = path.join("PublicStaging", packageName);
    const bundleId = await this.getBundleId(appPath);

    await this.uploadApp(appPath, destPackagePath);
    await this.installer.installApp(destPackagePath, bundleId);

    return bundleId;
  }

  private async uploadApp(srcPath: string, destPath: string) {
    try {
      await this.afc.getFileInfo("PublicStaging");
    } catch (err) {
      if (
        err instanceof AFCError &&
        err.status === AFCStatus.OBJECT_NOT_FOUND
      ) {
        await this.afc.makeDirectory("PublicStaging");
      } else {
        throw err;
      }
    }

    await this.afc.uploadDirectory(srcPath, destPath);
  }

  private async getBundleId(ipaPath: string): Promise<string> {
    const dir = await this.mkTempDir();
    await extract(ipaPath, { dir });

    const payloadPath = glob.sync(dir + '/Payload/*/')[0];
    const infoPath = payloadPath + 'Info.plist';

    const info = plist.parse(fs.readFileSync(infoPath).toString()) as plist.PlistObject;

    if (!info.CFBundleIdentifier) {
      throw new Error('Could not find bundle id');
    }

    return info.CFBundleIdentifier as string;
  }

  private mkTempDir(): Promise<string> {
    return new Promise((resolve, reject) => {
      fs.mkdtemp(path.join(os.tmpdir(), 'installApp'), (err, folder) => {
        if (err) {
          reject(err);
          return;
        }

        resolve(folder);
      });
    });
  }
}

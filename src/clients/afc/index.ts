import fs from "fs";
import type net from "net";
import path from "path";
import { promisify } from "util";

import {
  AFCResponse,
  AFCFileOpenFlags,
  AFCOperation,
  AFCStatus,
} from "../../protocols/afc/consts";
import { AFCError, AFCProtocolClient } from "../../protocols/afc";

import { ServiceClient } from "../client";

const MAX_OPEN_FILES = 240;

export class AFCClient extends ServiceClient<AFCProtocolClient> {
  constructor(public socket: net.Socket) {
    super(socket, new AFCProtocolClient(socket));
  }

  async getFileInfo(path: string): Promise<string[]> {
    const resp = await this.protocolClient.sendMessage({
      operation: AFCOperation.GET_FILE_INFO,
      data: toCString(path),
    });

    const strings: string[] = [];
    let currentString = "";
    const tokens = resp.data;
    tokens.forEach((token) => {
      if (token === 0) {
        strings.push(currentString);
        currentString = "";
      } else {
        currentString += String.fromCharCode(token);
      }
    });
    return strings;
  }

  async writeFile(fd: Buffer, data: Buffer): Promise<AFCResponse> {
    return this.protocolClient.sendMessage({
      operation: AFCOperation.FILE_WRITE,
      data: fd,
      payload: data,
    });
  }

  async openFile(path: string): Promise<Buffer> {
    // mode + path + null terminator
    const data = Buffer.alloc(8 + path.length + 1);
    // write mode
    data.writeUInt32LE(AFCFileOpenFlags.WRONLY, 0);
    // then path to file
    toCString(path).copy(data, 8);

    const resp = await this.protocolClient.sendMessage({
      operation: AFCOperation.FILE_OPEN,
      data,
    });

    if (resp.operation === AFCOperation.FILE_OPEN_RES) {
      return resp.data;
    }

    throw new Error(
      `There was an unknown error opening file ${path}, response: ${Array.prototype.toString.call(
        resp.data
      )}`
    );
  }

  async closeFile(fd: Buffer): Promise<AFCResponse> {
    return this.protocolClient.sendMessage({
      operation: AFCOperation.FILE_CLOSE,
      data: fd,
    });
  }

  async uploadFile(srcPath: string, destPath: string): Promise<void> {
    // read local file and get fd of destination
    const [srcFile, destFile] = await Promise.all([
      await promisify(fs.readFile)(srcPath),
      await this.openFile(destPath),
    ]);

    try {
      await this.writeFile(destFile, srcFile);
      await this.closeFile(destFile);
    } catch (err) {
      await this.closeFile(destFile);
      throw err;
    }
  }

  async makeDirectory(path: string): Promise<AFCResponse> {
    return this.protocolClient.sendMessage({
      operation: AFCOperation.MAKE_DIR,
      data: toCString(path),
    });
  }

  async uploadDirectory(srcPath: string, destPath: string): Promise<void> {
    await this.makeDirectory(destPath);

    let numOpenFiles = 0;
    const pendingFileUploads: (() => void)[] = [];
    const _this = this;
    return uploadDir(srcPath);

    async function uploadDir(dirPath: string): Promise<void> {
      const promises: Promise<void>[] = [];
      for (const file of fs.readdirSync(dirPath)) {
        const filePath = path.join(dirPath, file);
        const remotePath = path.join(
          destPath,
          path.relative(srcPath, filePath)
        );
        if (fs.lstatSync(filePath).isDirectory()) {
          promises.push(
            _this.makeDirectory(remotePath).then(() => uploadDir(filePath))
          );
        } else {
          // Create promise to add to promises array
          // this way it can be resolved once a pending upload has finished
          let resolve: (val?: any) => void;
          let reject: (err: AFCError) => void;
          const promise = new Promise<void>((res, rej) => {
            resolve = res;
            reject = rej;
          });
          promises.push(promise);

          // wrap upload in a function in case we need to save it for later
          const uploadFile = (tries = 0) => {
            numOpenFiles++;
            _this
              .uploadFile(filePath, remotePath)
              .then(() => {
                resolve();
                numOpenFiles--;
                const fn = pendingFileUploads.pop();
                if (fn) {
                  fn();
                }
              })
              .catch((err: AFCError) => {
                // Couldn't get fd for whatever reason, try again
                // # of retries is arbitrary and can be adjusted
                if (err.status === AFCStatus.NO_RESOURCES && tries < 10) {
                  uploadFile(tries++);
                } else {
                  numOpenFiles--;
                  reject(err);
                }
              });
          };

          if (numOpenFiles < MAX_OPEN_FILES) {
            uploadFile();
          } else {
            pendingFileUploads.push(uploadFile);
          }
        }
      }
      await Promise.all(promises);
    }
  }
}

function toCString(s: string) {
  const buf = Buffer.alloc(s.length + 1);
  const len = buf.write(s);
  buf.writeUInt8(0, len);
  return buf;
}

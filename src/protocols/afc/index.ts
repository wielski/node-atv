import type net from "net";

import type { ProtocolReaderCallback, ProtocolWriter } from "../protocol";
import {
  ProtocolClient,
  ProtocolReader,
  ProtocolReaderFactory,
} from "../protocol";

import {
  AFC_MAGIC,
  AFC_HEADER_SIZE,
  AFCStatus,
  AFCStatusResponse,
  AFCResponse,
  AFCMessage,
  AFCHeader,
  verifyResponse,
} from "./consts";

class AFCInternalError extends Error {
  constructor(msg: string, public requestId: number) {
    super(msg);
  }
}

export class AFCError extends Error {
  constructor(msg: string, public status: AFCStatus) {
    super(msg);
  }
}

export class AFCProtocolClient extends ProtocolClient {
  private requestId = 0;
  private requestCallbacks: { [key: number]: ProtocolReaderCallback } = {};

  constructor(socket: net.Socket) {
    super(
      socket,
      new ProtocolReaderFactory(AFCProtocolReader),
      new AFCProtocolWriter()
    );

    const reader = this.readerFactory.create((resp, err) => {
      if (err && err instanceof AFCInternalError) {
        this.requestCallbacks[err.requestId](resp, err);
      } else if (verifyResponse.isErrorStatusResponse(resp)) {
        this.requestCallbacks[resp.id](
          resp,
          new AFCError(AFCStatus[resp.data], resp.data)
        );
      } else {
        this.requestCallbacks[resp.id](resp);
      }
    });
    socket.on("data", reader.onData);
  }

  sendMessage(msg: AFCMessage): Promise<AFCResponse> {
    return new Promise<AFCResponse>((resolve, reject) => {
      const requestId = this.requestId++;
      this.requestCallbacks[requestId] = async (resp: any, err?: Error) => {
        if (err) {
          reject(err);
          return;
        }
        if (verifyResponse.isAFCResponse(resp)) {
          resolve(resp);
        } else {
          reject(new Error("Malformed AFC response"));
        }
      };
      this.writer.write(this.socket, { ...msg, requestId });
    });
  }
}

export class AFCProtocolReader extends ProtocolReader {
  private header!: AFCHeader;

  constructor(callback: ProtocolReaderCallback) {
    super(AFC_HEADER_SIZE, callback);
  }

  parseHeader(data: Buffer) {
    const magic = data.slice(0, 8).toString("ascii");
    if (magic !== AFC_MAGIC) {
      throw new AFCInternalError(
        `Invalid AFC packet received (magic != ${AFC_MAGIC})`,
        data.readUInt32LE(24)
      );
    }

    this.header = {
      magic,
      totalLength: data.readUInt32LE(8),
      headerLength: data.readUInt32LE(16),
      requestId: data.readUInt32LE(24),
      operation: data.readUInt32LE(32),
    };

    if (this.header.headerLength < AFC_HEADER_SIZE) {
      throw new AFCInternalError("Invalid AFC header", this.header.requestId);
    }
    return this.header.totalLength - AFC_HEADER_SIZE;
  }

  parseBody(data: Buffer): AFCResponse | AFCStatusResponse {
    const body: any = {
      operation: this.header.operation,
      id: this.header.requestId,
      data,
    };

    if (verifyResponse.isStatusResponse(body)) {
      const status = data.readUInt32LE(0);
      body.data = status;
    }

    return body;
  }
}

export class AFCProtocolWriter implements ProtocolWriter {
  write(socket: net.Socket, msg: AFCMessage & { requestId: number }) {
    const { data, payload, operation, requestId } = msg;

    const dataLength = data ? data.length : 0;
    const payloadLength = payload ? payload.length : 0;

    const header = Buffer.alloc(AFC_HEADER_SIZE);
    const magic = Buffer.from(AFC_MAGIC);
    magic.copy(header);
    header.writeUInt32LE(AFC_HEADER_SIZE + dataLength + payloadLength, 8);
    header.writeUInt32LE(AFC_HEADER_SIZE + dataLength, 16);
    header.writeUInt32LE(requestId, 24);
    header.writeUInt32LE(operation, 32);
    socket.write(header);
    socket.write(data);

    if (payload) {
      socket.write(payload);
    }
  }
}

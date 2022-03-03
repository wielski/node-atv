import type net from "net";
import plist from "plist";

export type ProtocolReaderCallback = (resp: any, err?: Error) => void;

export class ProtocolReaderFactory<T> {
  constructor(
    private ProtocolReader: new (callback: ProtocolReaderCallback) => T
  ) {}

  create(callback: (resp: any, err?: Error) => void): T {
    return new this.ProtocolReader(callback);
  }
}

export abstract class ProtocolReader {
  protected body!: Buffer;
  protected bodyLength!: number;
  protected buffer = Buffer.alloc(0);

  constructor(
    protected headerSize: number,
    protected callback: ProtocolReaderCallback
  ) {
    this.onData = this.onData.bind(this);
  }

  protected abstract parseHeader(data: Buffer): number;
  protected abstract parseBody(data: Buffer): any;

  onData(data?: Buffer) {
    try {
      this.buffer = data ? Buffer.concat([this.buffer, data]) : this.buffer;
      if (!this.bodyLength) {
        if (this.buffer.length < this.headerSize) {
          return;
        }
        this.bodyLength = this.parseHeader(this.buffer);
        this.buffer = this.buffer.slice(this.headerSize);
        if (!this.buffer.length) {
          return;
        }
      }
      if (this.buffer.length < this.bodyLength) {
        return;
      }

      if (this.bodyLength === -1) {
        this.callback(this.parseBody(this.buffer));
        this.buffer = Buffer.alloc(0);
      } else {
        this.body = this.buffer.slice(0, this.bodyLength);
        this.bodyLength -= this.body.length;
        if (!this.bodyLength) {
          this.callback(this.parseBody(this.body));
        }
        this.buffer = this.buffer.slice(this.body.length);
        if (this.buffer.length) {
          this.onData();
        }
      }
    } catch (err) {
      this.callback(null, err);
    }
  }
}

export abstract class PlistProtocolReader extends ProtocolReader {
  protected parseBody(body: Buffer) {
    return plist.parse(body.toString("utf8"));
  }

  onData(data?: Buffer) {
    this.buffer = data ? Buffer.concat([this.buffer, data]) : this.buffer;

    if (this.buffer.toString().indexOf("</plist>") > -1) {
      try {
        this.callback(this.parseBody(this.buffer));
      } catch (err) {
        this.callback(null, err);
      }
      this.buffer = Buffer.alloc(0);
    }
  }
}

export interface ProtocolWriter {
  write(sock: net.Socket, msg: any): void;
}

export abstract class ProtocolClient<MessageType = any> {
  constructor(
    public socket: net.Socket,
    protected readerFactory: ProtocolReaderFactory<ProtocolReader>,
    protected writer: ProtocolWriter
  ) {}

  sendMessage<ResponseType = any>(msg: MessageType): Promise<ResponseType>;
  sendMessage<CallbackType = void, ResponseType = any>(
    msg: MessageType,
    callback: (response: ResponseType, resolve: any, reject: any) => void
  ): Promise<CallbackType>;
  sendMessage<CallbackType = void, ResponseType = any>(
    msg: MessageType,
    callback?: (response: ResponseType, resolve: any, reject: any) => void
  ): Promise<CallbackType | ResponseType> {
    return new Promise<ResponseType | CallbackType>((resolve, reject) => {
      const reader = this.readerFactory.create(
        async (resp: ResponseType, err?: Error) => {
          if (err) {
            reject(err);
            return;
          }
          if (callback) {
            callback(
              resp,
              (value: any) => {
                this.socket.removeListener("data", reader.onData);
                resolve(value);
              },
              reject
            );
          } else {
            this.socket.removeListener("data", reader.onData);
            resolve(resp);
          }
        }
      );
      this.socket.on("data", reader.onData);
      this.writer.write(this.socket, msg);
    });
  }
}

import type net from 'net';

import type { ProtocolClient } from '../protocols/protocol';

export abstract class ServiceClient<T extends ProtocolClient> {
  constructor(public socket: net.Socket, protected protocolClient: T) {}
}

export class ResponseError extends Error {
  constructor(msg: string, public response: any) {
    super(msg);
  }
}

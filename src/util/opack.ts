export class OpackUUID {
  constructor(public value: string) {}
  
  toBuffer(): Buffer {
    return Buffer.from(this.value);
  }
}

export function opack_pack(data: any) {
  return _opack_pack(data);
}

function _opack_pack(data: any, object_list: Buffer[] = []): Buffer {
  let packed_bytes: Buffer;

  if (!data) {
    packed_bytes = Buffer.from([0x04]);
  } else if (typeof data == "boolean") {
    packed_bytes = Buffer.from([data ? 1 : 2]);
  } else if (data instanceof OpackUUID) {
    packed_bytes = Buffer.concat([Buffer.from([0x05]), data.toBuffer()]);
  } else if (typeof data == "number") {
    if (Number.isInteger(data)) {
      if (data < 0x28) {
        packed_bytes = Buffer.from([data + 8]);
      } else if (data <= 0xff) {
        const int = Buffer.alloc(1);
        int.writeUintBE(data, 0, 1);
        packed_bytes = Buffer.concat([Buffer.from([0x30]), int]);
      } else if (data <= 0xffff) {
        const int = Buffer.alloc(2);
        int.writeUintBE(data, 0, 2);
        packed_bytes = Buffer.concat([Buffer.from([0x31]), int]);
      } else if (data <= 0xffffffff) {
        const int = Buffer.alloc(3);
        int.writeUintBE(data, 0, 3);
        packed_bytes = Buffer.concat([Buffer.from([0x32]), int]);
      } else if (data <= 0xffffffffffffffff) {
        const int = Buffer.alloc(4);
        int.writeUintBE(data, 0, 4);
        packed_bytes = Buffer.concat([Buffer.from([0x33]), int]);
      }
    } else {
      const float = Buffer.alloc(4);
      float.writeFloatLE(data, 0);
      packed_bytes = Buffer.concat([Buffer.from([0x36]), float]);
    }
  } else if (typeof data == "string") {
    if (data.length <= 0x20) {
      packed_bytes = Buffer.concat([
        Buffer.from([0x40 + data.length]),
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xff) {
      const len = Buffer.alloc(1);
      len.writeUintBE(data.length, 0, 1);
      packed_bytes = Buffer.concat([
        Buffer.from([0x61]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffff) {
      const len = Buffer.alloc(2);
      len.writeUintBE(data.length, 0, 2);
      packed_bytes = Buffer.concat([
        Buffer.from([0x62]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffffff) {
      const len = Buffer.alloc(3);
      len.writeUintBE(data.length, 0, 3);
      packed_bytes = Buffer.concat([
        Buffer.from([0x63]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffffffff) {
      const len = Buffer.alloc(4);
      len.writeUintBE(data.length, 0, 4);
      packed_bytes = Buffer.concat([
        Buffer.from([0x64]),
        len,
        Buffer.from(data),
      ]);
    }
  } else if (Buffer.isBuffer(data)) {
    if (data.length <= 0x20) {
      packed_bytes = Buffer.concat([
        Buffer.from([0x70 + data.length]),
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xff) {
      const len = Buffer.alloc(1);
      len.writeUintBE(data.length, 0, 1);
      packed_bytes = Buffer.concat([
        Buffer.from([0x91]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffff) {
      const len = Buffer.alloc(2);
      len.writeUintBE(data.length, 0, 2);
      packed_bytes = Buffer.concat([
        Buffer.from([0x92]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffffff) {
      const len = Buffer.alloc(3);
      len.writeUintBE(data.length, 0, 3);
      packed_bytes = Buffer.concat([
        Buffer.from([0x93]),
        len,
        Buffer.from(data),
      ]);
    } else if (data.length <= 0xffffffff) {
      const len = Buffer.alloc(4);
      len.writeUintBE(data.length, 0, 4);
      packed_bytes = Buffer.concat([
        Buffer.from([0x94]),
        len,
        Buffer.from(data),
      ]);
    }
  } else if (Array.isArray(data)) {
    const arrayBuffer = data.map((i) => {
      return _opack_pack(i, object_list);
    });
    if (data.length >= 0xf) {
      arrayBuffer.push(Buffer.from([0x03]));
    }

    packed_bytes = Buffer.concat([
      Buffer.from([0xd0 + (data.length < 0xf ? data.length : 0xf)]),
      ...arrayBuffer,
    ]);
  } else if (typeof data == "object") {
    const arrayBuffer = [];
    for (const key in data) {
      const kBytes = _opack_pack(key, object_list);
      const vBytes = _opack_pack(data[key], object_list);
      arrayBuffer.push(Buffer.concat([kBytes, vBytes]));
    }

    const dataLength = Object.keys(data).length;

    if (dataLength >= 0xf) {
      arrayBuffer.push(Buffer.from([0x03]));
    }

    packed_bytes = Buffer.concat([
      Buffer.from([0xe0 + (dataLength < 0xf ? dataLength : 0xf)]),
      ...arrayBuffer,
    ]);
  } else {
    throw new Error(`Could not perform opack for ${data}`);
  }

  const packedBytesIndex = object_list.findIndex(
    (buf) => Buffer.compare(buf, packed_bytes) == 0
  );

  if (packedBytesIndex > -1) {
    packed_bytes = Buffer.from([0xa0 + packedBytesIndex]);
  } else if (packed_bytes.length > 1) {
    object_list.push(packed_bytes);
  }

  return packed_bytes;
}

export const AFC_MAGIC = "CFA6LPAA";
export const AFC_HEADER_SIZE = 40;

export interface AFCHeader {
  magic: typeof AFC_MAGIC;
  totalLength: number;
  headerLength: number;
  requestId: number;
  operation: AFCOperation;
}

export interface AFCMessage {
  operation: AFCOperation;
  data?: any;
  payload?: any;
}

export interface AFCResponse {
  operation: AFCOperation;
  id: number;
  data: Buffer;
}

export interface AFCStatusResponse {
  operation: AFCOperation.STATUS;
  id: number;
  data: number;
}

export enum AFCOperation {
  INVALID = 0x00000000,
  STATUS = 0x00000001,
  DATA = 0x00000002,
  READ_DIR = 0x00000003,
  READ_FILE = 0x00000004,
  WRITE_FILE = 0x00000005,
  WRITE_PART = 0x00000006,
  TRUNCATE = 0x00000007,
  REMOVE_PATH = 0x00000008,
  MAKE_DIR = 0x00000009,
  GET_FILE_INFO = 0x0000000a,
  GET_DEVINFO = 0x0000000b,
  WRITE_FILE_ATOM = 0x0000000c,
  FILE_OPEN = 0x0000000d,
  FILE_OPEN_RES = 0x0000000e,
  FILE_READ = 0x0000000f,
  FILE_WRITE = 0x00000010,
  FILE_SEEK = 0x00000011,
  FILE_TELL = 0x00000012,
  FILE_TELL_RES = 0x00000013,
  FILE_CLOSE = 0x00000014,
  FILE_SET_SIZE = 0x00000015,
  GET_CON_INFO = 0x00000016,
  SET_CON_OPTIONS = 0x00000017,
  RENAME_PATH = 0x00000018,
  SET_FS_BS = 0x00000019,
  SET_SOCKET_BS = 0x0000001a,
  FILE_LOCK = 0x0000001b,
  MAKE_LINK = 0x0000001c,
  GET_FILE_HASH = 0x0000001d,
  SET_FILE_MOD_TIME = 0x0000001e,
  GET_FILE_HASH_RANGE = 0x0000001f,
  FILE_SET_IMMUTABLE_HINT = 0x00000020,
  GET_SIZE_OF_PATH_CONTENTS = 0x00000021,
  REMOVE_PATH_AND_CONTENTS = 0x00000022,
  DIR_OPEN = 0x00000023,
  DIR_OPEN_RESULT = 0x00000024,
  DIR_READ = 0x00000025,
  DIR_CLOSE = 0x00000026,
  FILE_READ_OFFSET = 0x00000027,
  FILE_WRITE_OFFSET = 0x00000028,
}

export enum AFCStatus {
  SUCCESS = 0,
  UNKNOWN_ERROR = 1,
  OP_HEADER_INVALID = 2,
  NO_RESOURCES = 3,
  READ_ERROR = 4,
  WRITE_ERROR = 5,
  UNKNOWN_PACKET_TYPE = 6,
  INVALID_ARG = 7,
  OBJECT_NOT_FOUND = 8,
  OBJECT_IS_DIR = 9,
  PERM_DENIED = 10,
  SERVICE_NOT_CONNECTED = 11,
  OP_TIMEOUT = 12,
  TOO_MUCH_DATA = 13,
  END_OF_DATA = 14,
  OP_NOT_SUPPORTED = 15,
  OBJECT_EXISTS = 16,
  OBJECT_BUSY = 17,
  NO_SPACE_LEFT = 18,
  OP_WOULD_BLOCK = 19,
  IO_ERROR = 20,
  OP_INTERRUPTED = 21,
  OP_IN_PROGRESS = 22,
  INTERNAL_ERROR = 23,
  MUX_ERROR = 30,
  NO_MEM = 31,
  NOT_ENOUGH_DATA = 32,
  DIR_NOT_EMPTY = 33,
  FORCE_SIGNED_TYPE = -1,
}

export enum AFCFileOpenFlags {
  RDONLY = 0x00000001,
  RW = 0x00000002,
  WRONLY = 0x00000003,
  WR = 0x00000004,
  APPEND = 0x00000005,
  RDAPPEND = 0x00000006,
}

function isAFCResponse(resp: any): resp is AFCResponse {
  return (
    AFCOperation[resp.operation] !== undefined &&
    resp.id !== undefined &&
    resp.data !== undefined
  );
}

function isStatusResponse(resp: any): resp is AFCStatusResponse {
  return isAFCResponse(resp) && resp.operation === AFCOperation.STATUS;
}

function isErrorStatusResponse(resp: AFCResponse): boolean {
  return isStatusResponse(resp) && resp.data !== AFCStatus.SUCCESS;
}

export const verifyResponse = {
    isAFCResponse,
    isStatusResponse,
    isErrorStatusResponse,
};

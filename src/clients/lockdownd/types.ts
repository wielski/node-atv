export interface DeviceValues {
  BasebandCertId: number;
  BasebandKeyHashInformation: {
    AKeyStatus: number;
    SKeyHash: Buffer;
    SKeyStatus: number;
  };
  BasebandSerialNumber: Buffer;
  BasebandVersion: string;
  BoardId: number;
  BuildVersion: string;
  ChipID: number;
  DeviceClass: string;
  DeviceColor: string;
  DeviceName: string;
  DieID: number;
  HardwareModel: string;
  HasSiDP: boolean;
  PartitionType: string;
  ProductName: string;
  ProductType: string;
  ProductVersion: string;
  ProductionSOC: boolean;
  ProtocolVersion: string;
  TelephonyCapability: boolean;
  UniqueChipID: number;
  UniqueDeviceID: string;
  WiFiAddress: string;
  [key: string]: any;
}

export type DeviceValue = keyof DeviceValues;

export interface LockdowndServiceResponse {
  Request: "StartService";
  Service: string;
  Port: number;
  EnableServiceSSL?: boolean;
}

export interface LockdowndSessionResponse {
  Request: "StartSession";
  EnableSessionSSL: boolean;
}

export interface LockdowndAllValuesResponse {
  Request: "GetValue";
  Value: DeviceValues;
}

export interface LockdowndValueResponse {
  Request: "GetValue";
  Key: string;
  Value: string;
}

export interface LockdowndQueryTypeResponse {
  Request: "QueryType";
  Type: string;
}

export interface LockdowndInitialPairingResponse {
  Request: "CUPairingCreate";
  ExtendedResponse: {
    Payload: Buffer;
  };
}

export interface LockdowndPinPairingResponse {
  Request: "CUPairingCreate";
  ExtendedResponse: {
    Payload: Buffer;
  };
}

export interface LockdowndSsrPairingResponse {
  Request: "CUPairingCreate";
  ExtendedResponse: {
    Payload: Buffer;
    doSRPPair: string;
  };
}

function isLockdowndServiceResponse(
  resp: any
): resp is LockdowndServiceResponse {
  return (
    resp.Request === "StartService" &&
    resp.Service !== undefined &&
    resp.Port !== undefined
  );
}

function isLockdowndSessionResponse(
  resp: any
): resp is LockdowndSessionResponse {
  return resp.Request === "StartSession";
}

function isLockdowndAllValuesResponse(
  resp: any
): resp is LockdowndAllValuesResponse {
  return resp.Request === "GetValue" && resp.Value !== undefined;
}

function isLockdowndValueResponse(resp: any): resp is LockdowndValueResponse {
  return (
    resp.Request === "GetValue" &&
    resp.Key !== undefined &&
    typeof resp.Value === "string"
  );
}

function isLockdowndQueryTypeResponse(
  resp: any
): resp is LockdowndQueryTypeResponse {
  return resp.Request === "QueryType" && resp.Type !== undefined;
}

function isLockdowndInitialPairingResponse(
  resp: any
): resp is LockdowndInitialPairingResponse {
  return (
    resp.Request === "CUPairingCreate" && resp.ExtendedResponse !== undefined
  );
}

function isLockdowndPinPairingResponse(
  resp: any
): resp is LockdowndPinPairingResponse {
  return (
    resp.Request === "CUPairingCreate" && resp.ExtendedResponse !== undefined
  );
}

function isLockdowndSsrPairingResponse(
  resp: any
): resp is LockdowndSsrPairingResponse {
  return (
    resp.Request === "CUPairingCreate" &&
    resp.ExtendedResponse !== undefined &&
    resp.ExtendedResponse.doSRPPair !== undefined
  );
}

export const responseValidators = {
  isLockdowndServiceResponse,
  isLockdowndSessionResponse,
  isLockdowndAllValuesResponse,
  isLockdowndValueResponse,
  isLockdowndQueryTypeResponse,
  isLockdowndInitialPairingResponse,
  isLockdowndPinPairingResponse,
  isLockdowndSsrPairingResponse,
};

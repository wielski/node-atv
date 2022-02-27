import { LockdownResponse, LockdownCommand } from "../../protocols/lockdown";

export interface IPOptions {
  ApplicationsType?: "Any";
  PackageType?: "Developer";
  CFBundleIdentifier?: string;
  ReturnAttributes?: (
    | "CFBundleIdentifier"
    | "CFBundleExecutable"
    | "Container"
    | "Path"
  )[];
  BundleIDs?: string[];
}

export interface IPInstallPercentCompleteResponseItem extends LockdownResponse {
  PercentComplete: number;
}

export interface IPInstallCFBundleIdentifierResponseItem {
  CFBundleIdentifier: string;
}

export interface IPInstallCompleteResponseItem extends LockdownResponse {
  Status: "Complete";
}

export type IPInstallPercentCompleteResponse =
  IPInstallPercentCompleteResponseItem[];
export type IPInstallCFBundleIdentifierResponse =
  IPInstallCFBundleIdentifierResponseItem[];
export type IPInstallCompleteResponse = IPInstallCompleteResponseItem[];
export type IPInstallResponse = IPInstallPercentCompleteResponse | IPInstallCFBundleIdentifierResponse | IPInstallCompleteResponse;

export interface IPMessage extends LockdownCommand {
  Command: string;
  ClientOptions: IPOptions;
}

export interface IPLookupResponseItem extends LockdownResponse {
  LookupResult: IPLookupResult;
}

export type IPLookupResponse = IPLookupResponseItem[];

export interface IPLookupResult {
  [key: string]: {
    Container: string;
    CFBundleIdentifier: string;
    CFBundleExecutable: string;
    Path: string;
  };
}

function isIPLookupResponse(resp: any): resp is IPLookupResponse {
  return resp.length && resp[0].LookupResult !== undefined;
}

function isIPInstallPercentCompleteResponse(
  resp: any
): resp is IPInstallPercentCompleteResponse {
  return resp.length && resp[0].PercentComplete !== undefined;
}

function isIPInstallCFBundleIdentifierResponse(
  resp: any
): resp is IPInstallCFBundleIdentifierResponse {
  return resp.length && resp[0].CFBundleIdentifier !== undefined;
}

function isIPInstallCompleteResponse(
  resp: any
): resp is IPInstallCompleteResponse {
  return resp.length && resp[0].Status === "Complete";
}

export const validateResponse = {
  isIPLookupResponse,
  isIPInstallPercentCompleteResponse,
  isIPInstallCFBundleIdentifierResponse,
  isIPInstallCompleteResponse,
};

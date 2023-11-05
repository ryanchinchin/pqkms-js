export declare const isUND: (val: any) => boolean;
export { bytesToNumberBE, numberToBytesBE, utf8ToBytes, concatBytes, hexToBytes, numberToVarBytesBE, } from "@noble/curves/abstract/utils";
export type endian_t = "big" | "little";
export declare function assert(val: boolean): void;
export declare function eqArray(arr1: ArrayBuffer, arr2: ArrayBuffer): boolean;
export declare class ValidationError extends Error {
    constructor(message: string);
}
export declare class InvalidRequest extends Error {
    constructor(message: string);
}
export declare class AuthenticationFailed extends Error {
    readonly reason: string;
    readonly user_name: string;
    readonly domain: string;
    constructor(reason: string, user_name: string, domain: string);
}
export declare const fromHexString: (hexString: string) => ArrayBuffer;
export declare const toHexString: (bytes: ArrayBuffer) => string;
export declare const b64urlEncode: (buffer: ArrayBuffer) => string;
export declare const b64urlDecode: (b64encoded_data: string, endian?: endian_t) => ArrayBuffer;
export type BrowserType = "Opera" | "Edge" | "Chrome" | "Safari" | "Firefox" | "MSIE" | "Unknown";
export declare function browserType(): BrowserType;

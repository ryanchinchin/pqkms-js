export const isUND = (val) => {
    return typeof val === "undefined";
};
export { bytesToNumberBE, numberToBytesBE, utf8ToBytes, concatBytes, hexToBytes, numberToVarBytesBE, } from "@noble/curves/abstract/utils";
export function assert(val) {
    if (!val) {
        throw EvalError("Assertion failed");
    }
}
export function eqArray(arr1, arr2) {
    let a = new Uint8Array(arr1);
    let b = new Uint8Array(arr2);
    let result = arr1.byteLength == arr2.byteLength;
    let min_len = arr1.byteLength < arr2.byteLength ? arr1.byteLength : arr2.byteLength;
    for (let i = 0; i < min_len; i++) {
        result &&= a[i] === b[i];
    }
    return result;
}
export class ValidationError extends Error {
    constructor(message) {
        super(message);
        this.name = "ValidationError";
    }
}
export class InvalidRequest extends Error {
    constructor(message) {
        super(message);
        this.name = "InvalidRequest";
    }
}
export class AuthenticationFailed extends Error {
    reason;
    user_name;
    domain;
    constructor(reason, user_name, domain) {
        const m = `Authentication failed for user '${user_name}', project '${domain}'. Reason: ${reason}`;
        super(m);
        this.reason = reason;
        this.user_name = user_name;
        this.domain = domain;
        this.name = "AuthenticationFailed";
    }
}
export const fromHexString = (hexString) => {
    if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
        hexString = hexString.substring(2);
    }
    if (hexString.length % 2 !== 0) {
        hexString = `0${hexString}`;
    }
    let splits = hexString.match(/.{1,2}/g);
    if (splits) {
        return Uint8Array.from(splits.map((byte) => parseInt(byte, 16)));
    }
    else {
        return Uint8Array.from([]);
    }
};
export const toHexString = (bytes) => new Uint8Array(bytes).reduce((str, byte) => str + byte.toString(16).padStart(2, "0"), "");
export const b64urlEncode = function (buffer) {
    let ab = new Uint8Array(buffer);
    return btoa(Array.from(ab, (b) => String.fromCharCode(b)).join(""))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
};
export const b64urlDecode = function (b64encoded_data, endian = "little") {
    b64encoded_data = b64encoded_data.replace(/-/g, "+").replace(/_/g, "/");
    var pad = b64encoded_data.length % 4;
    if (pad) {
        if (pad === 1) {
            throw new Error("InvalidLengthError: Input base64url string is the wrong length to determine padding");
        }
        b64encoded_data += new Array(5 - pad).join("=");
    }
    let result = new ArrayBuffer(b64encoded_data.length);
    let dataView = new DataView(result);
    let counter = 0;
    if (endian === "little") {
        [...atob(b64encoded_data)]
            .slice()
            .reverse()
            .forEach((c) => dataView.setUint8(counter++, c.codePointAt(0)));
    }
    else {
        [...atob(b64encoded_data)].forEach((c) => dataView.setUint8(counter++, c.codePointAt(0)));
    }
    return result.slice(0, counter);
};
export function browserType() {
    if ((navigator.userAgent.indexOf("Opera") ||
        navigator.userAgent.indexOf("OPR")) != -1) {
        return "Opera";
    }
    else if (navigator.userAgent.indexOf("Edg") != -1) {
        return "Edge";
    }
    else if (navigator.userAgent.indexOf("Chrome") != -1) {
        return "Chrome";
    }
    else if (navigator.userAgent.indexOf("Safari") != -1) {
        return "Safari";
    }
    else if (navigator.userAgent.indexOf("Firefox") != -1) {
        return "Firefox";
    }
    else if (navigator.userAgent.indexOf("MSIE") != -1) {
        return "MSIE";
    }
    else {
        return "Unknown";
    }
}

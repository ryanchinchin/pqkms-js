export const isUND = (val: any): boolean => {
  return typeof val === "undefined";
};

export { concatBytes, utf8ToBytes, hexToBytes } from "@noble/hashes/utils";

export type endian_t = "big" | "little";

export function assert(val: boolean) {
  if (!val) {
    throw EvalError("Assertion failed");
  }
}

export function eqArray(arr1: ArrayBuffer, arr2: ArrayBuffer): boolean {
  let a = new Uint8Array(arr1);
  let b = new Uint8Array(arr2);
  let result = arr1.byteLength == arr2.byteLength;
  let min_len =
    arr1.byteLength < arr2.byteLength ? arr1.byteLength : arr2.byteLength;

  for (let i = 0; i < min_len; i++) {
    result &&= a[i] === b[i];
  }
  return result;
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export const fromHexString = (hexString: string): ArrayBuffer => {
  if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
    hexString = hexString.substring(2);
  }

  if (hexString.length % 2 !== 0) {
    hexString = `0${hexString}`;
  }

  let splits = hexString.match(/.{1,2}/g);
  if (splits) {
    return Uint8Array.from(splits.map((byte) => parseInt(byte, 16)));
  } else {
    return Uint8Array.from([]);
  }
};

export const toHexString = (bytes: ArrayBuffer) =>
  new Uint8Array(bytes).reduce(
    (str, byte) => str + byte.toString(16).padStart(2, "0"),
    ""
  );

export const b64urlEncode = function (buffer: ArrayBuffer) {
  let ab = new Uint8Array(buffer);
  return btoa(Array.from(ab, (b) => String.fromCharCode(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

export const b64urlDecode = function (
  b64encoded_data: string,
  endian: endian_t = "little"
): ArrayBuffer {
  b64encoded_data = b64encoded_data.replace(/-/g, "+").replace(/_/g, "/");

  var pad = b64encoded_data.length % 4;
  if (pad) {
    if (pad === 1) {
      throw new Error(
        "InvalidLengthError: Input base64url string is the wrong length to determine padding"
      );
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
  } else {
    [...atob(b64encoded_data)].forEach((c) =>
      dataView.setUint8(counter++, c.codePointAt(0))
    );
  }

  return result.slice(0, counter);
};

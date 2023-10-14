import {
  bytesToNumberBE,
  numberToBytesBE,
  utf8ToBytes,
  concatBytes,
  Hex,
} from "@noble/curves/abstract/utils";
import { Field, IField, mod } from "@noble/curves/abstract/modular";
import { CurveFn } from "@noble/curves/abstract/weierstrass";
import { H2CPoint, htfBasicOpts } from "@noble/curves/abstract/hash-to-curve";
import { sha512 } from "@noble/hashes/sha512";
import { hkdf } from "@noble/hashes/hkdf";

export * as utils from "@noble/curves/abstract/utils";

export type OprfErr = "HashedToInifinity" | "UnknownCurveType";

function num2b64(x: bigint | number, len: number): string {
  let buffer = numberToBytesBE(x, len);

  return btoa(Array.from(buffer, (b) => String.fromCharCode(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export class OprfError extends Error {
  constructor(readonly error_type: OprfErr) {
    super(error_type);
  }

  err(): OprfErr {
    return this.error_type;
  }
}

type FpField = IField<bigint> & Required<Pick<IField<bigint>, "isOdd">>;
type UnicodeOrBytes = string | Uint8Array;
type HashToCurveFn = (
  msg: Uint8Array,
  options?: htfBasicOpts
) => H2CPoint<bigint>;

export interface OprfClientInitData {
  hashed_password: UnicodeOrBytes;
  blinder: bigint;
  clientRequestBytes: string; // Hex encoded client's point
}

function toUtf8Bytes(input: UnicodeOrBytes): Uint8Array {
  if (typeof input == "string") {
    return utf8ToBytes(input);
  } else {
    return input;
  }
}

export class OprfClient {
  readonly EcGroup: CurveFn;
  readonly Fq: FpField;
  readonly hashToCurve: HashToCurveFn;
  readonly coordinateSize: number;

  constructor(ec_group: CurveFn, hashToCurve: HashToCurveFn) {
    this.EcGroup = ec_group;
    this.Fq = Field(this.EcGroup.CURVE.n);
    this.hashToCurve = hashToCurve;
    this.coordinateSize = this.EcGroup.CURVE.Fp.BYTES;
  }

  curveName(): string {
    const bits = this.EcGroup.CURVE.Fp.BITS;
    if (bits === 256) {
      return "P-256";
    } else if (bits === 384) {
      return "P-384";
    } else if (bits === 521) {
      return "P-521";
    } else {
      throw new OprfError("UnknownCurveType" as const);
    }
  }

  blind(hashed_password: UnicodeOrBytes): OprfClientInitData {
    let blinder = this.EcGroup.utils.randomPrivateKey();
    let blinder_int = bytesToNumberBE(blinder);
    if (blinder_int === BigInt(0)) {
      // recurse and retry -- It won't take long
      return this.blind(hashed_password);
    }
    let pwd = toUtf8Bytes(hashed_password);
    let clientRequest = this.hashToCurve(pwd).multiply(blinder_int);
    if (clientRequest.equals(this.EcGroup.ProjectivePoint.ZERO)) {
      throw new OprfError("HashedToInifinity");
    }

    let proj = this.EcGroup.ProjectivePoint.fromAffine(
      clientRequest.toAffine()
    );

    return {
      hashed_password,
      blinder: blinder_int,
      clientRequestBytes: proj.toHex(false),
    };
  }

  async finalize(
    evaluatedElement: Hex,
    clientData: OprfClientInitData
  ): Promise<Uint8Array> {
    let server_point = this.EcGroup.ProjectivePoint.fromHex(evaluatedElement);

    server_point.assertValidity();
    let uncompressed_bytes = server_point.toHex(false);
    if (uncompressed_bytes == clientData.clientRequestBytes) {
      throw Error(
        "Server tried to attack the client during OPRF finalize step by replaying the client's request"
      );
    }
    let inv_blind = this.Fq.inv(clientData.blinder);
    let final_point = server_point.multiply(inv_blind).toRawBytes(false);

    // See https://www.ietf.org/archive/id/draft-irtf-cfrg-voprf-21.html#section-3.3.1-6

    let hashInput = concatBytes(
      numberToBytesBE(clientData.hashed_password.length, 2),
      toUtf8Bytes(clientData.hashed_password),
      numberToBytesBE(final_point.length, 2),
      final_point,
      toUtf8Bytes("Finalize")
    );
    let digest = await globalThis.crypto.subtle.digest(
      "SHA-512",
      hashInput.buffer
    );
    return new Uint8Array(digest);
  }

  async login_key(
    session_key: Uint8Array,
    hashed_pw: UnicodeOrBytes
  ): Promise<{ loginKey: CryptoKey; publicKey: Uint8Array }> {
    const CURVE = this.EcGroup.CURVE;
    const ProjectivePoint = this.EcGroup.ProjectivePoint;
    const crypto = globalThis.crypto.subtle;

    const salt = concatBytes(
      toUtf8Bytes(hashed_pw),
      toUtf8Bytes("LoginInfoSalt")
    );
    const info = toUtf8Bytes("LoginInfo");

    let privateKeyInp = bytesToNumberBE(
      hkdf(sha512, session_key, salt, info, 512 / 8)
    );

    let loginKey = mod(privateKeyInp, CURVE.n);

    let publicPoint = ProjectivePoint.fromPrivateKey(loginKey);

    let jwk: JsonWebKey = {
      crv: this.curveName(),
      d: num2b64(loginKey, CURVE.nByteLength),
      ext: true,
      key_ops: ["sign"],
      kty: "EC",
      x: num2b64(publicPoint.x, CURVE.Fp.BYTES),
      y: num2b64(publicPoint.y, CURVE.Fp.BYTES),
    };

    let kk = await crypto.importKey(
      "jwk",
      jwk,
      {
        name: "ECDSA",
        namedCurve: this.curveName(),
      },
      true,
      ["sign"]
    );

    return { loginKey: kk, publicKey: publicPoint.toRawBytes(false) };
  }

  async lockbox_key(
    session_key: Uint8Array,
    hashed_pw: UnicodeOrBytes
  ): Promise<CryptoKey> {
    const crypto = globalThis.crypto.subtle;

    const salt = concatBytes(
      toUtf8Bytes(hashed_pw),
      toUtf8Bytes("LockboxSalt")
    );
    const info = toUtf8Bytes("LockboxKey");

    let aes_key_raw = hkdf(sha512, session_key, salt, info, 256 / 8);

    let aes_key = await crypto.importKey("raw", aes_key_raw, "AES-GCM", false, [
      "encrypt",
      "decrypt",
      "wrapKey",
      "unwrapKey",
    ]);

    return aes_key;
  }
}

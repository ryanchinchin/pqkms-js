import {
  bytesToHex,
  bytesToNumberBE,
  utf8ToBytes,
  concatBytes,
  numberToBytesBE,
  Hex,
} from "@noble/curves/abstract/utils";
import { Field, IField } from "@noble/curves/abstract/modular";
import { CurveFn } from "@noble/curves/abstract/weierstrass";
import { H2CPoint, htfBasicOpts } from "@noble/curves/abstract/hash-to-curve";

export * as utils from "@noble/curves/abstract/utils";

export type OprfErr = "HashedToInifinity";

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

  encodeUncompressed(point: H2CPoint<bigint>): Uint8Array {
    let affine_point = point.toAffine();
    let xbytes = numberToBytesBE(affine_point.x, this.coordinateSize);
    let ybytes = numberToBytesBE(affine_point.y, this.coordinateSize);
    let serialized_point = concatBytes(Uint8Array.from([0x4]), xbytes, ybytes);
    return serialized_point;
  }

  blind(hashed_password: UnicodeOrBytes): OprfClientInitData {
    let blinder = this.EcGroup.utils.randomPrivateKey();
    let blinder_int = bytesToNumberBE(blinder);
    if (blinder_int === BigInt(0)) {
      return this.blind(hashed_password);
    }
    let pwd = toUtf8Bytes(hashed_password);
    let clientRequest = this.hashToCurve(pwd).multiply(blinder_int);
    if (clientRequest.equals(this.EcGroup.ProjectivePoint.ZERO)) {
      throw new OprfError("HashedToInifinity");
    }

    return {
      blinder: blinder_int,
      clientRequestBytes: bytesToHex(this.encodeUncompressed(clientRequest)),
    };
  }

  finalize(evaluatedElement: Hex, clientData: OprfClientInitData): Uint8Array {
    let server_point = this.EcGroup.ProjectivePoint.fromHex(evaluatedElement);
    server_point.assertValidity();
    let inv_blind = this.Fq.inv(clientData.blinder);
    let final_point = server_point.multiply(inv_blind);
    return this.encodeUncompressed(final_point);
  }
}

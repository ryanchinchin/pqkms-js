import { Hex } from "@noble/curves/abstract/utils";
import { IField } from "@noble/curves/abstract/modular";
import { CurveFn } from "@noble/curves/abstract/weierstrass";
import { H2CPoint, htfBasicOpts } from "@noble/curves/abstract/hash-to-curve";
export * as utils from "@noble/curves/abstract/utils";
export type OprfErr = "HashedToInifinity";
export declare class OprfError extends Error {
    readonly error_type: OprfErr;
    constructor(error_type: OprfErr);
    err(): OprfErr;
}
type FpField = IField<bigint> & Required<Pick<IField<bigint>, "isOdd">>;
type UnicodeOrBytes = string | Uint8Array;
type HashToCurveFn = (msg: Uint8Array, options?: htfBasicOpts) => H2CPoint<bigint>;
export interface OprfClientInitData {
    blinder: bigint;
    clientRequestBytes: string;
}
export declare class OprfClient {
    readonly EcGroup: CurveFn;
    readonly Fq: FpField;
    readonly hashToCurve: HashToCurveFn;
    readonly coordinateSize: number;
    constructor(ec_group: CurveFn, hashToCurve: HashToCurveFn);
    encodeUncompressed(point: H2CPoint<bigint>): Uint8Array;
    blind(hashed_password: UnicodeOrBytes): OprfClientInitData;
    finalize(evaluatedElement: Hex, clientData: OprfClientInitData): Uint8Array;
}

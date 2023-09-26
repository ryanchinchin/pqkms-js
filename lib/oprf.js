import { bytesToHex, bytesToNumberBE, utf8ToBytes, concatBytes, numberToBytesBE, } from "@noble/curves/abstract/utils";
import { Field } from "@noble/curves/abstract/modular";
export * as utils from "@noble/curves/abstract/utils";
export class OprfError extends Error {
    error_type;
    constructor(error_type) {
        super(error_type);
        this.error_type = error_type;
    }
    err() {
        return this.error_type;
    }
}
function toUtf8Bytes(input) {
    if (typeof input == "string") {
        return utf8ToBytes(input);
    }
    else {
        return input;
    }
}
export class OprfClient {
    EcGroup;
    Fq;
    hashToCurve;
    coordinateSize;
    constructor(ec_group, hashToCurve) {
        this.EcGroup = ec_group;
        this.Fq = Field(this.EcGroup.CURVE.n);
        this.hashToCurve = hashToCurve;
        this.coordinateSize = this.EcGroup.CURVE.Fp.BYTES;
    }
    encodeUncompressed(point) {
        let affine_point = point.toAffine();
        let xbytes = numberToBytesBE(affine_point.x, this.coordinateSize);
        let ybytes = numberToBytesBE(affine_point.y, this.coordinateSize);
        let serialized_point = concatBytes(Uint8Array.from([0x4]), xbytes, ybytes);
        return serialized_point;
    }
    blind(hashed_password) {
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
    finalize(evaluatedElement, clientData) {
        let server_point = this.EcGroup.ProjectivePoint.fromHex(evaluatedElement);
        server_point.assertValidity();
        let inv_blind = this.Fq.inv(clientData.blinder);
        let final_point = server_point.multiply(inv_blind);
        return this.encodeUncompressed(final_point);
    }
}

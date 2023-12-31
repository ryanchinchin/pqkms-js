import { bytesToNumberBE, numberToBytesBE, utf8ToBytes, concatBytes, } from "@noble/curves/abstract/utils";
import { Field, mod } from "@noble/curves/abstract/modular";
export * as utils from "@noble/curves/abstract/utils";
function num2b64(x, len) {
    let buffer = numberToBytesBE(x, len);
    return btoa(Array.from(buffer, (b) => String.fromCharCode(b)).join(""))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
}
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
export var PrfMode;
(function (PrfMode) {
    PrfMode[PrfMode["OPRF"] = 0] = "OPRF";
    PrfMode[PrfMode["VOPRF"] = 1] = "VOPRF";
    PrfMode[PrfMode["POPRF"] = 2] = "POPRF";
})(PrfMode || (PrfMode = {}));
function mode2dst(mode) {
    let result = new Uint8Array(2);
    result[0] = mode;
    result[1] = 0x2d;
    return result;
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
    curveName() {
        const bits = this.EcGroup.CURVE.Fp.BITS;
        if (bits === 256) {
            return "P-256";
        }
        else if (bits === 384) {
            return "P-384";
        }
        else if (bits === 521) {
            return "P-521";
        }
        else {
            throw new OprfError("UnknownCurveType");
        }
    }
    hashAlgo() {
        const bits = this.EcGroup.CURVE.Fp.BITS;
        if (bits === 256) {
            return "SHA-256";
        }
        else if (bits === 384) {
            return "SHA-384";
        }
        else if (bits === 521) {
            return "SHA-512";
        }
        else {
            throw new OprfError("UnknownCurveType");
        }
    }
    cipersuiteId() {
        const bits = this.EcGroup.CURVE.Fp.BITS;
        if (bits === 256) {
            return "P256-SHA256";
        }
        else if (bits === 384) {
            return "P384-SHA384";
        }
        else if (bits === 521) {
            return "P521-SHA512";
        }
        else {
            throw new OprfError("UnknownCurveType");
        }
    }
    contextString(mode) {
        const bits = this.EcGroup.CURVE.Fp.BITS;
        let prefix = utf8ToBytes("HashToGroup-OPRFV1-");
        let mdst = mode2dst(mode);
        let id = utf8ToBytes(this.cipersuiteId());
        return concatBytes(prefix, mdst, id);
    }
    blind(hashed_password) {
        let blinder = this.EcGroup.utils.randomPrivateKey();
        let blinder_int = bytesToNumberBE(blinder);
        if (blinder_int === BigInt(0)) {
            return this.blind(hashed_password);
        }
        let pwd = toUtf8Bytes(hashed_password);
        const opts = {
            DST: this.contextString(PrfMode.OPRF),
        };
        let hashedPoint = this.hashToCurve(pwd, opts);
        let hp = this.EcGroup.ProjectivePoint.fromAffine(hashedPoint.toAffine());
        let clientRequest = hashedPoint.multiply(blinder_int);
        if (clientRequest.equals(this.EcGroup.ProjectivePoint.ZERO)) {
            throw new OprfError("HashedToInifinity");
        }
        let proj = this.EcGroup.ProjectivePoint.fromAffine(clientRequest.toAffine());
        return {
            hashed_password,
            blinder: blinder_int,
            clientRequestBytes: proj.toHex(false),
        };
    }
    async finalize(evaluatedElement, clientData) {
        const subtle = globalThis.crypto.subtle;
        let server_point = this.EcGroup.ProjectivePoint.fromHex(evaluatedElement);
        server_point.assertValidity();
        let uncompressed_bytes = server_point.toHex(false);
        if (uncompressed_bytes === clientData.clientRequestBytes) {
            throw Error("Server tried to attack the client during OPRF finalize step by replaying the client's request");
        }
        let inv_blind = this.Fq.inv(clientData.blinder);
        let final_point = server_point.multiply(inv_blind).toRawBytes(true);
        const hashInput = concatBytes(numberToBytesBE(clientData.hashed_password.length, 2), toUtf8Bytes(clientData.hashed_password), numberToBytesBE(final_point.length, 2), final_point, toUtf8Bytes("Finalize"));
        const hkdf_raw_key = await subtle.digest(this.hashAlgo(), hashInput);
        return subtle.importKey("raw", hkdf_raw_key, "HKDF", false, [
            "deriveBits",
            "deriveKey",
        ]);
    }
    async login_key(hkdf_key, hashed_pw) {
        const CURVE = this.EcGroup.CURVE;
        const ProjectivePoint = this.EcGroup.ProjectivePoint;
        const crypto = globalThis.crypto.subtle;
        const salt = concatBytes(toUtf8Bytes(hashed_pw), toUtf8Bytes("LoginKeySalt"));
        const info = toUtf8Bytes("LoginKey");
        const derived_scalar = await crypto.deriveBits({
            name: "HKDF",
            hash: "SHA-512",
            salt: salt.buffer,
            info: info.buffer,
        }, hkdf_key, 8 * ((3 * CURVE.nByteLength) / 2));
        let privateKeyInp = bytesToNumberBE(new Uint8Array(derived_scalar));
        let loginKey = mod(privateKeyInp, CURVE.n);
        let publicPoint = ProjectivePoint.fromPrivateKey(loginKey);
        let jwk = {
            crv: this.curveName(),
            d: num2b64(loginKey, CURVE.nByteLength),
            ext: true,
            key_ops: ["sign"],
            kty: "EC",
            x: num2b64(publicPoint.x, CURVE.Fp.BYTES),
            y: num2b64(publicPoint.y, CURVE.Fp.BYTES),
        };
        let kk = await crypto.importKey("jwk", jwk, {
            name: "ECDSA",
            namedCurve: this.curveName(),
        }, true, ["sign"]);
        return { loginKey: kk, publicKey: publicPoint.toRawBytes(false) };
    }
    async lockbox_key(hkdf_key, hashed_pw) {
        const crypto = globalThis.crypto.subtle;
        const salt = concatBytes(toUtf8Bytes(hashed_pw), toUtf8Bytes("LockboxSalt"));
        const info = toUtf8Bytes("LockboxKey");
        return crypto.deriveKey({
            name: "HKDF",
            hash: "SHA-256",
            salt: salt.buffer,
            info: info.buffer,
        }, hkdf_key, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
    }
}

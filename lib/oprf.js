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
        let proj = this.EcGroup.ProjectivePoint.fromAffine(clientRequest.toAffine());
        return {
            hashed_password,
            blinder: blinder_int,
            clientRequestBytes: proj.toHex(false),
        };
    }
    async finalize(evaluatedElement, clientData) {
        const subtle = window.crypto.subtle;
        let server_point = this.EcGroup.ProjectivePoint.fromHex(evaluatedElement);
        server_point.assertValidity();
        let uncompressed_bytes = server_point.toHex(false);
        if (uncompressed_bytes == clientData.clientRequestBytes) {
            throw Error("Server tried to attack the client during OPRF finalize step by replaying the client's request");
        }
        let inv_blind = this.Fq.inv(clientData.blinder);
        let final_point = server_point.multiply(inv_blind).toRawBytes(false);
        const hashInput = concatBytes(numberToBytesBE(clientData.hashed_password.length, 2), toUtf8Bytes(clientData.hashed_password), numberToBytesBE(final_point.length, 2), final_point, toUtf8Bytes("Finalize"));
        const hkdf_raw_key = await subtle.digest("SHA-512", hashInput);
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
        const derived_scalar = await window.crypto.subtle.deriveBits({
            name: "HKDF",
            hash: "SHA-512",
            salt: salt.buffer,
            info: info.buffer,
        }, hkdf_key, 2 * CURVE.nByteLength * 8);
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
        return window.crypto.subtle.deriveKey({
            name: "HKDF",
            hash: "SHA-512",
            salt: salt.buffer,
            info: info.buffer,
        }, hkdf_key, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt", "wrapKey", "unwrapKey"]);
    }
}

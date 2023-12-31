import { assert, isUND, b64urlDecode, browserType } from "./utils.js";
export const extractModulus = async (key, endian = "little") => {
    assert(key.algorithm.name === "RSASSA-PKCS1-v1_5");
    let pub_json = await EnclaveSigner.hsm().exportKey("jwk", key);
    assert(!isUND(pub_json.kty) &&
        !isUND(pub_json.e) &&
        !isUND(pub_json.n) &&
        (pub_json.kty === "RSA" || pub_json.kty === "rsa"));
    const pub_exp = b64urlDecode(pub_json.e);
    assert(pub_exp.byteLength == 1 && new DataView(pub_exp).getUint8(0) === 0x3);
    return b64urlDecode(pub_json.n, endian);
};
export class EnclaveSigner {
    static CRYPTO = globalThis.crypto;
    constructor() {
        if (!globalThis.crypto || !globalThis.crypto.subtle) {
            throw Error("Either this connection is not secure or the browser doesn't support WebCrypto");
        }
    }
    static hsm() {
        return EnclaveSigner.CRYPTO.subtle;
    }
    uuid() {
        return EnclaveSigner.CRYPTO.randomUUID();
    }
    async sgx_rsa_key() {
        if (browserType() === "Safari") {
            const { sgxCompatKey } = await import("./compat");
            return sgxCompatKey(EnclaveSigner.hsm());
        }
        else {
            const publicExponent = new Uint8Array([0x03]);
            const usage = ["sign", "verify"];
            const params = {
                name: "RSASSA-PKCS1-v1_5",
                modulusLength: 3072,
                publicExponent,
                hash: "SHA-256",
            };
            const key = await EnclaveSigner.hsm().generateKey(params, true, usage);
            return key;
        }
    }
    async sign_enclave(tbsData, signingKey) {
        assert(signingKey.type === "private");
        assert(signingKey.algorithm.name === "RSASSA-PKCS1-v1_5");
        return EnclaveSigner.hsm().sign(signingKey.algorithm.name, signingKey, tbsData);
    }
    async verify_enclave(tbsData, signature, signingPubKey) {
        assert(signingPubKey.algorithm.name === "RSASSA-PKCS1-v1_5");
        assert(signingPubKey.type === "public");
        return EnclaveSigner.hsm().verify(signingPubKey.algorithm.name, signingPubKey, signature, tbsData);
    }
}

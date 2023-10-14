import * as argon2 from "argon2-wasm-esm";
import { OprfClient, OprfError } from "./oprf.js";
import { p384, hashToCurve } from "@noble/curves/p384";
import { utf8ToBytes, concatBytes } from "@noble/curves/abstract/utils";
const argon_config = {
    time: 2,
    mem: 19456,
    parallelism: 1,
    type: argon2.ArgonType.Argon2di,
};
const isUND = (val) => {
    return typeof val === "undefined";
};
function assert(val) {
    if (!val) {
        throw EvalError("Assertion failed");
    }
}
function eqArray(arr1, arr2) {
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
const extractModulus = async (key, endian = "little") => {
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
const default_v0_url_directory = {
    attestation: "/v0/admin/attestation",
    registration_init: "/v0/admin/reg_init",
    enclave_list: "/v0/admin/enclaves",
    registration_finish: "/v0/admin/reg_finish",
};
export default class UserRegistrationManager {
    discoveryURL;
    baseURL;
    oprfClient;
    oprfClientData = null;
    urlDirectory = null;
    constructor(directoryUrl) {
        this.discoveryURL = directoryUrl;
        const url = new URL(this.discoveryURL);
        this.baseURL = url.origin;
        this.oprfClient = new OprfClient(p384, hashToCurve);
    }
    async computeOprfClientData(raw_pw, user_info) {
        for (let i = 0; i < 5; i++) {
            let argon_hash = await pwhash(user_info.domain_name, user_info.email_addr, raw_pw, i);
            try {
                this.oprfClientData = this.oprfClient.blind(argon_hash);
                return this.oprfClientData;
            }
            catch (e) {
                if (e instanceof OprfError) {
                    if (e.err() == "HashedToInifinity") {
                        continue;
                    }
                }
                throw e;
            }
        }
        throw new Error("Unusable password!");
    }
    async parseServerResponse(response) {
        if (response.ok) {
            const resp = await response.json();
            if (resp.code >= 200 && resp.code < 300) {
                return resp.message;
            }
            else {
                throw new Error(`Server returned unexpected response with code: ${resp.code} and message: ${resp.message}`);
            }
        }
        else {
            const err_resp = await response.json();
            throw new Error(`Server error: ${err_resp.code} => ${err_resp.message}`);
        }
    }
    async fetchDirectory() {
        if (this.urlDirectory) {
            return this.urlDirectory;
        }
        try {
            const response = await fetch(this.discoveryURL, {
                mode: "cors",
            });
            if (response.status >= 200 && response.status < 300) {
                let versioned_directory = await response.json();
                this.urlDirectory = versioned_directory.v0;
            }
            else {
                this.urlDirectory = default_v0_url_directory;
            }
        }
        catch (e) {
            this.urlDirectory = default_v0_url_directory;
        }
        return this.urlDirectory;
    }
    async fetchEnclaveList() {
        let directory = await this.fetchDirectory();
        const fetchUrl = `${this.baseURL}${directory.enclave_list}`;
        const response = await fetch(fetchUrl, {
            mode: "cors",
        });
        const resp = await this.parseServerResponse(response);
        return resp;
    }
    async signEnclaves(privateKey, publicKey, modulesReq) {
        const enclaveSigner = new EnclaveSigner();
        assert(privateKey.type === "private");
        assert(publicKey.type === "public");
        let modulus = await extractModulus(publicKey, "big");
        let result = {
            user_info: null,
            server_nonce: null,
            signer_modulus: toHexString(modulus),
            signed_enclaves: [],
        };
        for (let enclave of modulesReq.enclaves) {
            const tbs_data = fromHexString(enclave.tbs_data);
            const sighash = fromHexString(enclave.sighash);
            const expected_sighash = await EnclaveSigner.hsm().digest("SHA-256", tbs_data);
            let entry = {
                is_ok: false,
                signature: "",
                enclave_name: enclave.enclave_name,
                config: enclave.config,
            };
            if (!eqArray(sighash, expected_sighash)) {
                entry.signature =
                    "Enclave sighash and SHA256(to-be-signed) do not match.";
            }
            else {
                const sig = await enclaveSigner.sign_enclave(tbs_data, privateKey);
                (entry.is_ok = true), (entry.signature = toHexString(sig));
                result.signed_enclaves.push(entry);
            }
        }
        return result;
    }
    async pssSign(domain_name, email_addr, login_pub, enclave_keypair) {
        const rsa_priv = await EnclaveSigner.hsm().exportKey("pkcs8", enclave_keypair.privateKey);
        const pss_signer = await EnclaveSigner.hsm().importKey("pkcs8", rsa_priv, {
            name: "RSA-PSS",
            hash: "SHA-256",
        }, false, ["sign"]);
        let tbs_data = concatBytes(utf8ToBytes(domain_name), utf8ToBytes(email_addr), login_pub);
        let pss_signature = await EnclaveSigner.hsm().sign({
            name: "RSA-PSS",
            saltLength: 32,
        }, pss_signer, tbs_data);
        return new Uint8Array(pss_signature);
    }
    async regFinalMsg(reg_init_msg, login_pub, enclave_keypair, ecdsa_login_key, lockbox_key) {
        const pop_challenge = await this.pssSign(reg_init_msg.user_info.domain_name, reg_init_msg.user_info.email_addr, login_pub, enclave_keypair);
        const pop_proof = await EnclaveSigner.hsm().sign({
            name: "ECDSA",
            hash: "SHA-384",
        }, ecdsa_login_key, pop_challenge);
        let iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const wrapped_data = await EnclaveSigner.hsm().wrapKey("pkcs8", enclave_keypair.privateKey, lockbox_key, {
            name: "AES-GCM",
            iv: iv,
        });
        const aux_data = `${b64urlEncode(iv)}.${b64urlEncode(wrapped_data)}`;
        const finish_msg = {
            server_nonce: reg_init_msg.server_nonce,
            aead_data: reg_init_msg.aead_data,
            user_pub: toHexString(login_pub),
            user_pub_sig: toHexString(pop_challenge),
            oprf_pop_sig: toHexString(pop_proof),
            aux_data,
        };
        return finish_msg;
    }
    async regInit(raw_pw, user_info, signing_key) {
        const { privateKey: signing_priv, publicKey: mrsigner_pub } = signing_key;
        assert(signing_priv.type === "private");
        assert(mrsigner_pub.type === "public");
        let directory = await this.fetchDirectory();
        let enclaves = await this.fetchEnclaveList();
        let signed = await this.signEnclaves(signing_priv, mrsigner_pub, enclaves);
        await this.computeOprfClientData(raw_pw, user_info);
        user_info.auth_data = this.oprfClientData.clientRequestBytes;
        signed.user_info = user_info;
        signed.server_nonce = enclaves.resp_challenge;
        let reg_init_url = `${this.baseURL}${directory.registration_init}`;
        let registerResult = await fetch(reg_init_url, {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(signed),
        });
        return this.parseServerResponse(registerResult);
    }
    async regFinal(init_resp, enclave_keypair) {
        const directory = await this.fetchDirectory();
        const session_key = await this.oprfClient.finalize(init_resp.user_info.auth_data, this.oprfClientData);
        const { loginKey, publicKey: login_pub } = await this.oprfClient.login_key(session_key, this.oprfClientData.hashed_password);
        const lockbox_key = await this.oprfClient.lockbox_key(session_key, this.oprfClientData.hashed_password);
        const final_msg = await this.regFinalMsg(init_resp, login_pub, enclave_keypair, loginKey, lockbox_key);
        let reg_fini_url = `${this.baseURL}${directory.registration_finish}`;
        const json_data = JSON.stringify(final_msg);
        let final_result = await fetch(reg_fini_url, {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            headers: {
                "Content-Type": "application/json",
            },
            body: json_data,
        });
        return this.parseServerResponse(final_result);
    }
}
export function validateDomainStr(domain) {
    const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$/g;
    const found = domain.match(regex);
    if (!found) {
        throw new ValidationError("Invalid domain prefix. Must be a valid domain component");
    }
}
export function validateRawPasswordStr(password) {
    if (password.length < 8) {
        throw new ValidationError("Invalid password. Must be at least 8 characters");
    }
}
export function validateUsernameStr(user_email) { }
export async function pwhash(domain, username, passwd, repeat) {
    let salt_pt = passwd + domain + username + passwd;
    if (repeat != null) {
        for (let j = 0; j < repeat; j++) {
            salt_pt = `${passwd}${salt_pt}${passwd}`;
        }
    }
    const argon_salt = new TextEncoder().encode(salt_pt);
    const salt = new Uint8Array(await EnclaveSigner.hsm().digest("SHA-256", argon_salt));
    const argon_hash = await argon2.hash({
        pass: passwd,
        salt,
        ...argon_config,
    });
    return argon_hash.hash;
}
export async function register_user(domain, email_addr, password, base_url, crypto_key) {
    validateDomainStr(domain);
    validateRawPasswordStr(password);
    validateUsernameStr(email_addr);
    const key_pair = crypto_key || (await new EnclaveSigner().sgx_rsa_key());
    let user = {
        domain_name: domain,
        email_addr: email_addr,
        auth_algo: "OPRF.P384-SHA384",
        auth_data: null,
    };
    let reg = new UserRegistrationManager(base_url);
    const reg_init_data = await reg.regInit(password, user, key_pair);
    await reg.regFinal(reg_init_data, key_pair);
}

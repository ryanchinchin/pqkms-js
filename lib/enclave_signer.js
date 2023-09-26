import * as argon2 from "argon2-wasm-esm";
import { OprfClient, OprfError } from "./oprf";
import { p384, hashToCurve } from "@noble/curves/p384";
// This is based on OWASP recommendataion from
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const argon_config = {
    time: 2,
    mem: 19456,
    parallelism: 1,
    type: argon2.ArgonType.Argon2di, // or argon2.ArgonType.Argon2i
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
        let usage = ["sign", "verify"];
        let params = {
            name: "RSASSA-PKCS1-v1_5",
            modulusLength: 3072,
            publicExponent,
            hash: "SHA-256",
        };
        const start_time = performance.now();
        const key = await EnclaveSigner.hsm().generateKey(params, false, usage);
        const end_time = performance.now();
        console.log("Time taken to generate RSA key: ", end_time - start_time);
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
        // let hdrs = new Map(response.headers);
        console.log(`Server returned response code: ${response.status} ${response.statusText} with headers:\n ${response.headers}`);
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
            console.log(`Server fetch returned code: ${response.status}`);
            if (response.status >= 200 && response.status < 300) {
                this.urlDirectory = await response.json();
            }
            else {
                this.urlDirectory = {
                    enclave_list: "/v0/admin/enclaves",
                    register_domain: "/v0/admin/register_domain",
                };
            }
        }
        catch (e) {
            console.log(`Error getting enclave directory: ${e}`);
            this.urlDirectory = {
                enclave_list: "/v0/admin/enclaves",
                register_domain: "/v0/admin/register_domain",
            };
        }
        console.log(`Using URL directory: ${this.urlDirectory}`);
        return this.urlDirectory;
    }
    async fetchEnclaveList() {
        let directory = await this.fetchDirectory();
        const fetchUrl = `${this.baseURL}${directory.enclave_list}`;
        console.log(`Attempting to fetch the list of enclaves from ${fetchUrl}!`);
        const response = await fetch(fetchUrl, {
            mode: "cors",
        });
        const resp = await this.parseServerResponse(response);
        return resp;
    }
    async signEnclaves(enclaveSigningKey, modulesReq) {
        const enclaveSigner = new EnclaveSigner();
        let { privateKey, publicKey } = enclaveSigningKey;
        assert(privateKey.type === "private");
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
    async registerUser(raw_pw, user_info, progress) {
        console.log(`Fetching enclave directory`);
        let directory = await this.fetchDirectory();
        console.log(`Fetching list of enclaves`);
        let enclaves = await this.fetchEnclaveList();
        console.log(`Signing enclaves`);
        let signed = await this.signEnclaves(user_info.enclave_key, enclaves);
        console.log(`Computing OPRF Client Data`);
        await this.computeOprfClientData(raw_pw, user_info);
        user_info.oprf_client_data = this.oprfClientData.clientRequestBytes;
        signed.user_info = user_info;
        signed.server_nonce = enclaves.resp_challenge;
        console.log(`Attempting stage-1 of registration`);
        let register_url = `${this.baseURL}${directory.register_domain}`;
        try {
            let registerResult = await fetch(register_url, {
                method: "POST",
                mode: "cors",
                cache: "no-cache",
                headers: {
                    "Content-Type": "application/json",
                },
                body: JSON.stringify(signed),
            });
            let resp = await this.parseServerResponse(registerResult);
            if (resp.code >= 200 && resp.code < 300) {
                return true;
            }
            else {
                return false;
            }
        }
        catch (e) {
            return false;
        }
    }
}
export function validate_domain_str(domain) {
    const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$/g;
    const found = domain.match(regex);
    if (!found) {
        throw new ValidationError("Invalid domain prefix. Must be a valid domain component");
    }
}
export function validate_raw_password_str(password) {
    if (password.length < 8) {
        throw new ValidationError("Invalid password. Must be at least 8 characters");
    }
}
export function validate_username_str(user_email) { }
export async function pwhash(domain, username, passwd, repeat // Used to avoid hashing to point at infinity
) {
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
    validate_domain_str(domain);
    validate_raw_password_str(password);
    validate_username_str(email_addr);
    let reg = new UserRegistrationManager(base_url);
    const enclaveKey = crypto_key || (await new EnclaveSigner().sgx_rsa_key());
    let user = {
        domain_name: domain,
        email_addr: email_addr,
        enclave_key: enclaveKey,
        oprf_client_data: null,
    };
    const registerUser = await reg.registerUser(password, user);
    console.log(`Registration `, registerUser ? "Successful" : "Failed");
}

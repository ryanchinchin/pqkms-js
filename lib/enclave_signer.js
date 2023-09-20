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
            throw Error("This environment doesn't support WebCrypto interface");
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
    urlDirectory = null;
    constructor(directoryUrl = "https://Euler.local:8443/") {
        this.discoveryURL = directoryUrl;
        const url = new URL(this.discoveryURL);
        this.baseURL = url.origin;
    }
    async parseServerResponse(response) {
        // let hdrs = new Map(response.headers);
        console.log(`Server returned response code: ${response.status} ${response.statusText} with headers:\n ${response.headers}`);
        if (response.ok) {
            const resp = await response.json();
            if (resp.code === 200) {
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
            if (response.status === 200) {
                this.urlDirectory = await response.json();
            }
            else {
                console.log(`Server returned non-200 response!`);
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
        console.log(`Attempting to fetch list of enclaves!`);
        const response = await fetch(fetchUrl, {
            mode: "cors",
        });
        const resp = await this.parseServerResponse(response);
        return resp;
    }
    async signEnclaves(userInfo, modulesReq) {
        const enclaveSigner = new EnclaveSigner();
        let { privateKey, publicKey } = userInfo.enclave_key;
        assert(privateKey.type === "private");
        let modulus = await extractModulus(publicKey, "big");
        let result = {
            user_info: {
                domain_name: userInfo.domain_name,
                email_addr: userInfo.email_addr,
            },
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
    async registerUser(user_info) {
        let enclaves = await this.fetchEnclaveList();
        let signed = await this.signEnclaves(user_info, enclaves);
        let directory = await this.fetchDirectory();
        let register_url = `${this.baseURL}${directory.register_domain}`;
        console.log(`Attempting to register user at URL ${register_url}`);
        signed.server_nonce = enclaves.resp_challenge;
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
export async function main() {
    let reg = new UserRegistrationManager();
    const crypto = new EnclaveSigner();
    const enclaveKey = await crypto.sgx_rsa_key();
    let user = {
        domain_name: "hakuna",
        email_addr: "hakuna@matata.com",
        enclave_key: enclaveKey,
    };
    const registerUser = await reg.registerUser(user);
    console.log(`Registration `, registerUser ? "Successful" : "Failed");
}

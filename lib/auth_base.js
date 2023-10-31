import { toHexString, hexToBytes } from "./utils.js";
import { OprfClient, OprfError } from "./oprf.js";
import { p384, hashToCurve } from "@noble/curves/p384";
export function to_auth_info(user_info) {
    const { domain_name, user_name, auth_algo, auth_data, salt } = user_info;
    return {
        domain_name,
        user_name,
        auth_data,
        auth_algo,
        salt,
    };
}
export class UserAuthBase {
    discoveryURL;
    baseURL;
    oprfClient;
    oprfClientData = null;
    constructor(directoryUrl) {
        if (!globalThis.crypto || !globalThis.crypto.subtle) {
            throw Error("Either this connection is not secure or the browser doesn't support WebCrypto");
        }
        this.discoveryURL = directoryUrl;
        const url = new URL(this.discoveryURL);
        this.baseURL = url.origin;
        this.oprfClient = new OprfClient(p384, hashToCurve);
    }
    async computeOprfClientData(raw_pw, user_info) {
        try {
            let salt = null;
            if (user_info.salt) {
                salt = user_info.salt;
            }
            else {
                salt = window.crypto.getRandomValues(new Uint8Array(32));
            }
            user_info.salt = toHexString(salt);
            const password = await pwhash(raw_pw, user_info, p384.CURVE.nByteLength);
            this.oprfClientData = this.oprfClient.blind(password);
            return this.oprfClientData;
        }
        catch (e) {
            if (e instanceof OprfError) {
                if (e.err() == "HashedToInifinity") {
                    return this.computeOprfClientData(raw_pw, user_info);
                }
            }
            throw e;
        }
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
    async fetchUserInfo(user_name, domain_name, auth_algo) {
        const directory = await this.fetchDirectory();
        let user_info_url = `${this.discoveryURL}${directory.user_info}?user_name=${user_name}`;
        if (domain_name) {
            user_info_url = `${user_info_url}&domain=${domain_name}`;
        }
        if (auth_algo) {
            user_info_url = `${user_info_url}&domain=${auth_algo}`;
        }
        const response = await fetch(user_info_url, {
            mode: "cors",
            cache: "no-store",
        });
        return this.parseServerResponse(response);
    }
}
export async function pwhash(passwd, user_info, key_length_bytes) {
    const pwd_pt = passwd + user_info.domain_name + user_info.user_name + passwd;
    const raw_pwd = await globalThis.crypto.subtle.importKey("raw", new TextEncoder().encode(pwd_pt), {
        name: "PBKDF2",
    }, false, ["deriveBits"]);
    let salt = hexToBytes(user_info.salt);
    let key = await globalThis.crypto.subtle.deriveBits({
        name: "PBKDF2",
        salt,
        iterations: 1000000,
        hash: "SHA-256",
    }, raw_pwd, 8 * key_length_bytes);
    return new Uint8Array(key);
}

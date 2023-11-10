import { UserAuthBase, } from "./auth_base.js";
import { InvalidRequest, ValidationError, AuthenticationFailed, assert, fromHexString, toHexString, b64urlDecode, } from "./utils";
const X_AUTHORIZATION_TOKEN = "X-Authorization-PQKMS-Token";
class AuthIO {
    login_data;
    lockbox_key;
    subtle;
    constructor(login_data, lockbox_key, subtle) {
        this.login_data = login_data;
        this.lockbox_key = lockbox_key;
        this.subtle = subtle;
        this.subtle = this.subtle || globalThis.crypto.subtle;
    }
    async fetch(url, method, data, headers) {
        if (this.login_data.auth_token.length === 0) {
            throw new InvalidRequest("User unauthenticated");
        }
        let hdrs = headers || {};
        hdrs["Authorization"] = `Bearer ${this.login_data.auth_token}`;
        let body = null;
        if (data) {
            hdrs["Content-Type"] = hdrs["Content-Type"] || "application/json";
            body = JSON.stringify(data);
        }
        let response = await fetch(url, {
            method,
            mode: "cors",
            cache: "no-cache",
            keepalive: true,
            headers: hdrs,
            body,
        });
        return this.parse(response);
    }
    async parse(response) {
        if (response.ok) {
            const resp = await response.json();
            if (resp.code >= 200 && resp.code < 300) {
                return resp.message;
            }
            else {
                throw new Error(`${resp.message}`);
            }
        }
        else {
            const err_resp = await response.json();
            throw new Error(`${JSON.stringify(err_resp)}`);
        }
    }
    async enclaveSigningKey() {
        if (!this.lockbox_key || !this.login_data.aux_data) {
            throw new InvalidRequest("enclave signing key unavailable");
        }
        let values = this.login_data.aux_data.split(`.`);
        if (values.length !== 2) {
            throw new InvalidRequest("Invalid auxilary data");
        }
        const iv = b64urlDecode(values[0], "big");
        const wrapped_key = b64urlDecode(values[1], "big");
        return this.subtle.unwrapKey("pkcs8", wrapped_key, this.lockbox_key, {
            name: "AES-GCM",
            iv: iv,
        }, {
            name: "RSASSA-PKCS1-v1_5",
            hash: "SHA-256",
        }, true, ["sign"]);
    }
}
const default_v0_app_directory = {
    attestation: "/v0/admin/attestation",
    login_init: "/v0/admin/login_init",
    login_finish: "/v0/admin/login_finish",
    user_info: "/v0/admin/user_info",
};
export default class AuthManager extends UserAuthBase {
    directory = null;
    constructor(directoryUrl) {
        super(directoryUrl);
    }
    async loginFinalMsg(msg, login_key) {
        let challenge = fromHexString(msg.challenge);
        let signature = await globalThis.crypto.subtle.sign({
            name: "ECDSA",
            hash: "SHA-384",
        }, login_key, challenge);
        msg.user_info.auth_data = toHexString(signature);
        return msg;
    }
    async fetchDirectory() {
        if (this.directory) {
            return this.directory;
        }
        try {
            const response = await fetch(this.discoveryURL, {
                mode: "cors",
                cache: "no-store",
                keepalive: true,
            });
            if (response.ok) {
                let versioned_directory = await response.json();
                this.directory = versioned_directory.v0;
            }
            else {
                this.directory = default_v0_app_directory;
            }
        }
        catch (e) {
            this.directory = default_v0_app_directory;
        }
        return this.directory;
    }
    async loginInit(auth_info, raw_pw) {
        const directory = await this.fetchDirectory();
        let clientData = await this.computeOprfClientData(raw_pw, auth_info);
        auth_info.auth_data = clientData.clientRequestBytes;
        let login_init_url = `${this.baseURL}${directory.login_init}`;
        delete auth_info.salt;
        let registerResult = await fetch(login_init_url, {
            method: "POST",
            mode: "cors",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(auth_info),
            keepalive: true,
        });
        return this.parseServerResponse(registerResult);
    }
    async loginFinal(login_init_resp) {
        const directory = await this.fetchDirectory();
        const session_key = await this.oprfClient.finalize(login_init_resp.user_info.auth_data, this.oprfClientData);
        const { loginKey } = await this.oprfClient.login_key(session_key, this.oprfClientData.hashed_password);
        const final_msg = await this.loginFinalMsg(login_init_resp, loginKey);
        const json_data = JSON.stringify(final_msg);
        let login_fini_url = `${this.baseURL}${directory.login_finish}`;
        let final_result = await fetch(login_fini_url, {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            headers: {
                "Content-Type": "application/json",
                "Access-Control-Request-Headers": X_AUTHORIZATION_TOKEN,
            },
            body: json_data,
        });
        if (final_result.ok) {
            let lockbox_key = null;
            const auth_token = final_result.headers.get(X_AUTHORIZATION_TOKEN);
            const resp = await this.parseServerResponse(final_result);
            assert(auth_token === resp.auth_token);
            if (resp.aux_data && resp.aux_data.length > 0) {
                lockbox_key = await this.oprfClient.lockbox_key(session_key, this.oprfClientData.hashed_password);
            }
            return new AuthIO(resp, lockbox_key);
        }
        else {
            try {
                this.parseServerResponse(final_result);
                throw new ValidationError(`Authentication failed with error code: ${final_result.status}`);
            }
            catch (e) {
                throw new AuthenticationFailed(`${e.message}`, login_init_resp.user_info.user_name, login_init_resp.user_info.domain_name);
            }
        }
    }
}
export async function login_user(domain_name, user_name, raw_passwd, salt, auth_algo, access_url) {
    const auth_manager = new AuthManager(access_url);
    let user_info = {
        domain_name,
        user_name,
        salt,
        auth_algo,
        auth_data: null,
    };
    let login_msg = await auth_manager.loginInit(user_info, raw_passwd);
    return auth_manager.loginFinal(login_msg);
}

import { UserAuthBase, } from "./auth_base.js";
import { fromHexString, toHexString } from "./utils";
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
            },
            body: json_data,
        });
        return final_result.ok;
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

import {
    UserAuthBase,
    URLVersionedDirectory,
    UserAuthInfo,
    UserInfo,
    to_auth_info,
} from "./auth_base.js";

import { InvalidRequest, assert } from "./utils";

export interface ProjectDirectory {
    attestation: string;
    login_init: string;
    login_finish: string;
    user_info: string;
}

interface LoginMessage {
    server_nonce: string;
    challenge: string;
    user_info: UserAuthInfo;
}

const default_v0_app_directory: ProjectDirectory = {
    attestation: "/v0/admin/attestation",
    login_init: "/v0/admin/login_init",
    login_finish: "/v0/admin/reg_finish",
    user_info: "/v0/admin/user_info",
};

export default class AuthManager extends UserAuthBase {
    protected directory: ProjectDirectory | null = null;

    constructor(directoryUrl: string) {
        super(directoryUrl);
    }

    async loginFinalMsg(msg: LoginMessage): Promise<LoginMessage> {
        return msg;
    }

    async fetchDirectory(): Promise<ProjectDirectory> {
        if (this.directory) {
            return this.directory;
        }

        try {
            const response = await fetch(super.discoveryURL, {
                mode: "cors",
                cache: "no-store",
            });
            // console.log(`Server fetch returned code: ${response.status}`);

            if (response.ok) {
                let versioned_directory: URLVersionedDirectory<ProjectDirectory> =
                    await response.json();
                this.directory = versioned_directory.v0;
            } else {
                this.directory = default_v0_app_directory;
            }
        } catch (e) {
            // console.log(`Error getting enclave directory: ${e}`);
            this.directory = default_v0_app_directory;
        }
        // console.log(`Using URL directory: ${this.urlDirectory}`);

        return this.directory!;
    }

    // Compute init request data given input from `loginInit` request
    async loginInit(
        user_name: string,
        domain_name: string,
        raw_pw: string
    ): Promise<LoginMessage> {
        // console .log(`Fetching enclave directory`);
        const directory = await this.fetchDirectory();
        const user_info_list = await this.fetchUserInfo(user_name, domain_name);

        let user_info: UserInfo;

        if (user_info_list.length === 0) {
            throw new InvalidRequest(
                `No record found for user '${user_name}' and project name ${domain_name}`
            );
        } else if (user_info_list.length > 1) {
            throw new InvalidRequest(
                `Server misconfiguration. Has more than one entry for user '${user_name}' and project '${domain_name}'`
            );
        } else {
            console.log(
                `Found user_info for user '${user_name}' and project '${domain_name}'`
            );

            user_info = user_info_list[0];
        }

        assert(!user_info);
        assert(user_info.auth_algo === "OPRF.P384-SHA384");

        let user_auth_info: UserAuthInfo = to_auth_info(user_info);
        let clientData = await this.computeOprfClientData(raw_pw, user_auth_info);
        user_auth_info.auth_data = clientData.clientRequestBytes;
        let login_init_url = `${this.baseURL}${directory.login_init}`;

        delete user_auth_info.salt;

        let registerResult = await fetch(login_init_url, {
            method: "POST",
            mode: "cors",
            cache: "no-store",
            headers: {
                "Content-Type": "application/json",
            },
            body: JSON.stringify(user_auth_info),
        });
        return this.parseServerResponse<LoginMessage>(registerResult);
    }

    // Compute the final response data given input from `loginInit` request
    async loginFinal(login_init_resp: LoginMessage): Promise<boolean> {
        const directory = await this.fetchDirectory();

        // console .log(`Finalizing OPRF session key`);
        const session_key = await this.oprfClient.finalize(
            login_init_resp.user_info.auth_data!,
            this.oprfClientData!
        );

        // console .log(`Computing OPRF login key`);
        const { loginKey, publicKey: login_pub } = await this.oprfClient.login_key(
            session_key,
            this.oprfClientData!.hashed_password
        );

        const final_msg = await this.loginFinalMsg(login_init_resp);
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

export async function login_user(
    domain_name: string,
    user_name: string,
    raw_passwd: string,
    auth_algo: string
): Promise<boolean> {
    return false;
}

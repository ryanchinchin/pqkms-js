import { UserAuthBase, UserAuthInfo } from "./auth_base.js";
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
export default class AuthManager extends UserAuthBase {
    protected directory: ProjectDirectory | null;
    constructor(directoryUrl: string);
    loginFinalMsg(msg: LoginMessage, login_key: CryptoKey): Promise<LoginMessage>;
    fetchDirectory(): Promise<ProjectDirectory>;
    loginInit(auth_info: UserAuthInfo, raw_pw: string): Promise<LoginMessage>;
    loginFinal(login_init_resp: LoginMessage): Promise<boolean>;
}
export declare function login_user(domain_name: string, user_name: string, raw_passwd: string, salt: string, auth_algo: string, access_url: string): Promise<boolean>;
export {};

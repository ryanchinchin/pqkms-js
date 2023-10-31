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
    loginFinalMsg(msg: LoginMessage): Promise<LoginMessage>;
    fetchDirectory(): Promise<ProjectDirectory>;
    loginInit(user_name: string, domain_name: string, raw_pw: string): Promise<LoginMessage>;
    loginFinal(login_init_resp: LoginMessage): Promise<boolean>;
}
export declare function login_user(domain_name: string, user_name: string, raw_passwd: string, auth_algo: string): Promise<boolean>;
export {};

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
interface LoginFinalResp {
    user_name: string;
    domain: string;
    auth_token: string;
    aux_data?: string;
    not_before: string;
    not_after: string;
}
declare class AuthIO {
    private readonly login_data;
    private readonly lockbox_key?;
    private readonly subtle?;
    constructor(login_data: LoginFinalResp, lockbox_key?: CryptoKey, subtle?: SubtleCrypto);
    fetch<U, T>(url: string | URL | Request, method: string, data?: T, headers?: HeadersInit): Promise<U>;
    private parse;
    enclaveSigningKey(): Promise<CryptoKey>;
}
export default class AuthManager extends UserAuthBase {
    protected directory: ProjectDirectory | null;
    constructor(directoryUrl: string);
    loginFinalMsg(msg: LoginMessage, login_key: CryptoKey): Promise<LoginMessage>;
    fetchDirectory(): Promise<ProjectDirectory>;
    loginInit(auth_info: UserAuthInfo, raw_pw: string): Promise<LoginMessage>;
    loginFinal(login_init_resp: LoginMessage): Promise<AuthIO>;
}
export declare function login_user(domain_name: string, user_name: string, raw_passwd: string, salt: string, auth_algo: string, access_url: string): Promise<AuthIO>;
export {};

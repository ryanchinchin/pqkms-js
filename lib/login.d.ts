import { OprfClient, OprfClientInitData } from "./oprf.js";
export interface UserAuthInfo {
    domain_name: string;
    user_name: string;
    auth_algo: string;
    auth_data: string | null;
    salt: string | null;
}
export interface UserInfo extends UserAuthInfo {
    mrsigner: string;
    aux_data?: string;
}
export interface URLVersionedDirectory<T> {
    v0: T;
}
export interface ProjectDirectory {
    attestation: string;
    login_init: string;
    login_finish: string;
    user_info: string;
}
export interface RegistrationDirectory {
    attestation: string;
    registration_init: string;
    enclave_list: string;
    registration_finish: string;
    user_info: string;
}
export type UrlDirectory = ProjectDirectory | RegistrationDirectory;
export declare class UserAuthManager {
    readonly discoveryURL: string;
    readonly baseURL: string;
    readonly oprfClient: OprfClient;
    protected oprfClientData: OprfClientInitData | null;
    protected directory: UrlDirectory;
    constructor(directoryUrl: string);
    computeOprfClientData(raw_pw: string, user_info: UserAuthInfo): Promise<OprfClientInitData>;
    parseServerResponse<T>(response: Response): Promise<T>;
    fetchDirectory(): Promise<UrlDirectory>;
    fetchUserInfo(user_name: string): Promise<Array<UserInfo>>;
}
export declare function pwhash(passwd: string, user_info: UserAuthInfo, key_length_bytes: number): Promise<Uint8Array>;

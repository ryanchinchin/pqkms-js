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
    access_url?: string;
}
export declare function to_auth_info(user_info: UserInfo): UserAuthInfo;
export interface URLVersionedDirectory<T> {
    v0: T;
}
export declare abstract class UserAuthBase {
    readonly discoveryURL: string;
    readonly baseURL: string;
    readonly oprfClient: OprfClient;
    protected oprfClientData: OprfClientInitData | null;
    constructor(directoryUrl: string);
    computeOprfClientData(raw_pw: string, user_info: UserAuthInfo): Promise<OprfClientInitData>;
    parseServerResponse<T>(response: Response): Promise<T>;
    abstract fetchDirectory(): Promise<any>;
    fetchUserInfo(user_name: string, domain_name?: string, auth_algo?: string): Promise<Array<UserInfo>>;
}
export declare function pwhash(passwd: string, user_info: UserAuthInfo, key_length_bytes: number): Promise<Uint8Array>;

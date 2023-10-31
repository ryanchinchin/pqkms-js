export interface UserProjectsInfo {
    domain_name: string;
    user_name: string;
    auth_algo: string;
    mrsigner: string;
    access_url: string;
}
export declare function register_user(domain: string, user_name: string, password: string, base_url: string, crypto_key?: CryptoKeyPair): Promise<void>;
export declare function login_user(user_projs: UserProjectsInfo): Promise<void>;
export declare function fetch_user_projects(registration_url: string, user_name: string): Promise<Array<UserProjectsInfo>>;

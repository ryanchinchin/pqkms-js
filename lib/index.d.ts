export interface UserProjectsInfo {
    domain_name: string;
    user_name: string;
    salt: string;
    auth_algo: string;
    mrsigner: string;
    access_url: string;
}
export declare function register_user(domain: string, user_name: string, password: string, base_url: string, crypto_key?: CryptoKeyPair): Promise<string>;
export declare function login_user(pi: UserProjectsInfo, raw_passwd: string): Promise<boolean>;
export declare function fetch_user_projects(registration_url: string, user_name: string): Promise<Array<UserProjectsInfo>>;

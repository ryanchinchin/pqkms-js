type endian_t = "big" | "little";
export declare class ValidationError extends Error {
    constructor(message: string);
}
export declare const fromHexString: (hexString: string) => ArrayBuffer;
export declare const toHexString: (bytes: ArrayBuffer) => string;
export declare const b64urlDecode: (b64encoded_data: string, endian?: endian_t) => ArrayBuffer;
interface EnclaveConfig {
    mrenclave: string;
    attributes: string[];
    xfrm: string[];
    misc: string[];
    cet: string[];
    max_thread_count?: number;
    product_family?: string;
    product_name?: string;
    product_id?: number;
    security_version?: number;
}
interface SigStructTbsInfo {
    enclave_name: string;
    sighash: string;
    tbs_data: string;
    config: EnclaveConfig;
}
interface ListModulesServerResponse {
    req_challenge: string;
    resp_challenge: string;
    enclaves: SigStructTbsInfo[];
}
interface SigStructClientSigned {
    is_ok: boolean;
    signature: string;
    enclave_name: string;
    config: EnclaveConfig;
}
interface UserInfo {
    domain_name: string;
    email_addr: string;
    enclave_key?: CryptoKeyPair;
}
interface ClientRequestForRegistration {
    user_info: UserInfo;
    server_nonce: string;
    signer_modulus: string;
    signed_enclaves: SigStructClientSigned[];
}
export declare class EnclaveSigner {
    static CRYPTO: Crypto;
    constructor();
    static hsm(): SubtleCrypto;
    uuid(): string;
    sgx_rsa_key(): Promise<CryptoKeyPair>;
    sign_enclave(tbsData: ArrayBuffer, signingKey: CryptoKey): Promise<ArrayBuffer>;
    verify_enclave(tbsData: ArrayBuffer, signature: ArrayBuffer, signingPubKey: CryptoKey): Promise<boolean>;
}
interface URLDirectory {
    enclave_list: string;
    register_domain: string;
}
export default class UserRegistrationManager {
    readonly discoveryURL: string;
    readonly baseURL: string;
    urlDirectory: URLDirectory;
    constructor(directoryUrl?: string);
    parseServerResponse(response: Response): Promise<any>;
    fetchDirectory(): Promise<URLDirectory>;
    fetchEnclaveList(): Promise<ListModulesServerResponse>;
    signEnclaves(userInfo: UserInfo, modulesReq: ListModulesServerResponse): Promise<ClientRequestForRegistration>;
    registerUser(user_info: UserInfo): Promise<boolean>;
}
export declare function main(): Promise<void>;
export {};

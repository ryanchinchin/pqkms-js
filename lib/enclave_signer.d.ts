import { OprfClient, OprfClientInitData } from "./oprf.js";
type endian_t = "big" | "little";
interface ActivityCallback<T> {
    start(): any;
    end(is_success: boolean): any;
}
interface RegistrationProgressCallback {
    fetchDirectory: ActivityCallback<void> | null;
    keygen: ActivityCallback<CryptoKeyPair> | null;
    sign: ActivityCallback<[SigStructTbsInfo]> | null;
    oprf: ActivityCallback<OprfClientInitData> | null;
    registrationInit: ActivityCallback<void> | null;
    registrationFinal: ActivityCallback<void> | null;
}
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
interface RegistrationReqInitMsg {
    domain_name: string;
    email_addr: string;
    oprf_client_data: string;
    enclave_key?: CryptoKeyPair;
}
interface ClientRequestForRegistration {
    user_info: RegistrationReqInitMsg | null;
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
    readonly oprfClient: OprfClient;
    private oprfClientData;
    urlDirectory: URLDirectory;
    constructor(directoryUrl: string);
    computeOprfClientData(raw_pw: string, user_info: RegistrationReqInitMsg): Promise<OprfClientInitData>;
    parseServerResponse(response: Response): Promise<any>;
    fetchDirectory(): Promise<URLDirectory>;
    fetchEnclaveList(): Promise<ListModulesServerResponse>;
    signEnclaves(enclaveSigningKey: CryptoKeyPair, modulesReq: ListModulesServerResponse): Promise<ClientRequestForRegistration>;
    registerUser(raw_pw: string, user_info: RegistrationReqInitMsg, progress?: RegistrationProgressCallback): Promise<boolean>;
}
export declare function validate_domain_str(domain: string): void;
export declare function validate_raw_password_str(password: string): void;
export declare function validate_username_str(user_email: string): void;
export declare function pwhash(domain: string, username: string, passwd: string, repeat?: number): Promise<Uint8Array>;
export declare function register_user(domain: string, email_addr: string, password: string, base_url: string, crypto_key?: CryptoKeyPair): Promise<void>;
export {};

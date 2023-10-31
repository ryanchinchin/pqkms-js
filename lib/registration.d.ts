import { UserAuthBase, UserAuthInfo } from "./auth_base.js";
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
interface ClientRegInit {
    user_info: UserAuthInfo | null;
    server_nonce: string;
    signer_modulus: string;
    signed_enclaves: SigStructClientSigned[];
}
interface RegInitResp {
    server_nonce: string;
    aead_data: string;
    user_info: UserAuthInfo;
}
interface ClientRegFinish {
    server_nonce: string;
    aead_data: string;
    user_pub: string;
    user_pub_sig: string;
    oprf_pop_sig: string;
    aux_data: string;
}
export interface RegistrationDirectory {
    attestation: string;
    registration_init: string;
    enclave_list: string;
    registration_finish: string;
    user_info: string;
}
export default class UserRegistrationManager extends UserAuthBase {
    protected directory: RegistrationDirectory | null;
    constructor(directoryUrl: string);
    fetchDirectory(): Promise<RegistrationDirectory>;
    fetchEnclaveList(): Promise<ListModulesServerResponse>;
    signEnclaves(privateKey: CryptoKey, publicKey: CryptoKey, modulesReq: ListModulesServerResponse): Promise<ClientRegInit>;
    pssSign(domain_name: string, email_addr: string, login_pub: Uint8Array, enclave_keypair: CryptoKeyPair): Promise<Uint8Array>;
    regFinalMsg(reg_init_msg: RegInitResp, login_pub: Uint8Array, enclave_keypair: CryptoKeyPair, ecdsa_login_key: CryptoKey, lockbox_key: CryptoKey): Promise<ClientRegFinish>;
    regInit(raw_pw: string, user_info: UserAuthInfo, signing_key: CryptoKeyPair): Promise<RegInitResp>;
    regFinal(init_resp: RegInitResp, enclave_keypair: CryptoKeyPair): Promise<string>;
}
export declare function validateDomainStr(domain: string): void;
export declare function validateRawPasswordStr(password: string): void;
export declare function validateUsernameStr(user_email: string): void;
export declare function register_user(domain: string, email_addr: string, password: string, base_url: string, crypto_key?: CryptoKeyPair): Promise<void>;
export {};

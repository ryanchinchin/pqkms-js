import { endian_t } from "./utils.js";
export declare const extractModulus: (key: CryptoKey, endian?: endian_t) => Promise<ArrayBuffer>;
export declare class EnclaveSigner {
    static CRYPTO: Crypto;
    constructor();
    static hsm(): SubtleCrypto;
    uuid(): string;
    sgx_rsa_key(): Promise<CryptoKeyPair>;
    sign_enclave(tbsData: ArrayBuffer, signingKey: CryptoKey): Promise<ArrayBuffer>;
    verify_enclave(tbsData: ArrayBuffer, signature: ArrayBuffer, signingPubKey: CryptoKey): Promise<boolean>;
}

export interface XYPair {
    x: bigint;
    y: bigint;
}
export interface Xgcd {
    g: bigint;
    u: bigint;
    v: bigint;
}
export declare function xgcd(a: bigint, b: bigint): Xgcd;
export declare function sgxCompatKey(subtle: SubtleCrypto): Promise<CryptoKeyPair>;

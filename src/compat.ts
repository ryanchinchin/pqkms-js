import {
  assert,
  b64urlDecode,
  b64urlEncode,
  bytesToNumberBE,
  numberToVarBytesBE,
} from "./utils";

import { mod, pow } from "@noble/curves/abstract/modular";

export interface XYPair {
  x: bigint;
  y: bigint;
}

export interface Xgcd {
  g: bigint;
  u: bigint;
  v: bigint;
}

// Returns Xgcd such that g = a_orig * u + b_orig * v
export function xgcd(a: bigint, b: bigint): Xgcd {
  let r0: bigint;
  let r1: bigint;
  let s0: bigint = 1n;
  let s1: bigint = 0n;
  let t0: bigint = 0n;
  let t1: bigint = 1n;

  // Invariant: r0 > r1

  if (a < b) {
    [r0, r1] = [b, a];
  } else {
    [r0, r1] = [a, b];
  }

  while (r1 !== 0n) {
    let q = r0 / r1;
    [r1, r0] = [r0 - q * r1, r1];
    [s1, s0] = [s0 - q * s1, s1];
    [t1, t0] = [t0 - q * t1, t1];
  }

  if (a < b) {
    return { g: r0, u: t0, v: s0 };
  } else {
    return { g: r0, u: s0, v: t0 };
  }
}

function twoadic_split(val: bigint): XYPair {
  let xy: XYPair = {
    x: val,
    y: 0n,
  };

  while ((xy.x & 0x1n) === 0x0n) {
    xy.y += 1n;
    xy.x >>= 1n;
  }
  return xy;
}

function factor(e: bigint, d: bigint, n: bigint): XYPair {
  const phi_mult = e * d - 1n;
  const { x: unit_exp, y: two_adic_val } = twoadic_split(phi_mult);

  let base = 2n;

  while (1) {
    let x = pow(base, unit_exp, n);
    if (x !== 1n && x !== n - 1n) {
      let y = x;
      for (let h = 1; h <= two_adic_val; h++) {
        const z = y * y;
        const zmod = mod(z, n);
        if (zmod === n - 1n) {
          break;
        } else if (zmod === 1n) {
          const { g: p } = xgcd(y - 1n, n);
          assert(n % p === 0n);
          const q = n / p;

          return {
            x: p,
            y: q,
          };
        } else {
          y = z;
        }
      }
    }
    base = base + 1n;
  }

  return { x: 0n, y: 0n };
}

async function genSgxKeyFromPrimes(
  subtle: SubtleCrypto,
  p: bigint,
  q: bigint
): Promise<CryptoKeyPair> {
  const n = p * q;
  const phi = (p - 1n) * (q - 1n);
  const e = 3n;
  let { g, v: d } = xgcd(phi, 3n);
  assert(g === 1n);
  while (d < 0) {
    d += phi;
  }
  const dp = mod(d, p - 1n);
  const dq = mod(d, q - 1n);
  let { u: qinv } = xgcd(q, p);

  while (qinv < 0n) {
    qinv += p;
  }

  assert((qinv * q) % p === 1n);

  const e_bytes = numberToVarBytesBE(e);
  const d_bytes = numberToVarBytesBE(d);
  const n_bytes = numberToVarBytesBE(n);
  const p_bytes = numberToVarBytesBE(p);
  const q_bytes = numberToVarBytesBE(q);
  const dp_bytes = numberToVarBytesBE(dp);
  const dq_bytes = numberToVarBytesBE(dq);
  const q_inv_bytes = numberToVarBytesBE(qinv + 1n);

  const k: JsonWebKey = {
    kty: "RSA",
    alg: "RS256",
    n: b64urlEncode(n_bytes),
    e: b64urlEncode(e_bytes),
    d: b64urlEncode(d_bytes),
    p: b64urlEncode(p_bytes),
    q: b64urlEncode(q_bytes),
    ext: true,
    key_ops: ["sign"],
    dp: b64urlEncode(dp_bytes),
    dq: b64urlEncode(dq_bytes),
    qi: b64urlEncode(q_inv_bytes),
  };

  const k_pub: JsonWebKey = {
    kty: "RSA",
    alg: "RS256",
    n: b64urlEncode(n_bytes),
    e: b64urlEncode(e_bytes),
    ext: true,
    key_ops: ["verify"],
  };

  const privKey = await subtle.importKey(
    "jwk",
    k,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["sign"]
  );

  const pubKey = await subtle.importKey(
    "jwk",
    k_pub,
    {
      name: "RSASSA-PKCS1-v1_5",
      hash: "SHA-256",
    },
    true,
    ["verify"]
  );

  return { privateKey: privKey, publicKey: pubKey };
}

export async function sgxCompatKey(
  subtle: SubtleCrypto
): Promise<CryptoKeyPair> {
  let count = 0;
  const publicExponent = new Uint8Array([0x01, 0x00, 0x01]);
  const usage: KeyUsage[] = ["sign", "verify"];

  const params: RsaHashedKeyGenParams = {
    name: "RSASSA-PKCS1-v1_5",
    modulusLength: 3072,
    publicExponent,
    hash: "SHA-256",
  };

  while (true) {
    const kp = await subtle.generateKey(params, true, usage);
    const jwt = await subtle.exportKey("jwk", kp.privateKey);
    const n_bytes = new Uint8Array(b64urlDecode(jwt.n, "big"));
    const d_bytes = new Uint8Array(b64urlDecode(jwt.d, "big"));
    const e = 0x010001n;
    const d = bytesToNumberBE(d_bytes);
    const n = bytesToNumberBE(n_bytes);
    let { x: p, y: q } = factor(e, d, n);
    if ((p - 1n) % 3n == 0n || (q - 1n) % 3n == 0n) {
      continue;
    } else {
      return genSgxKeyFromPrimes(subtle, p, q);
    }
  }
}

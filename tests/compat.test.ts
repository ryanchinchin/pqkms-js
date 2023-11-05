import { xgcd, sgxCompatKey } from "../lib/compat.js";
import { assert } from "../lib/utils.js";
import * as crypto from "node:crypto";

function ab2str(buf) {
  return String.fromCharCode.apply(null, new Uint8Array(buf));
}

async function exportPrivKey(
  subtle: SubtleCrypto,
  key: CryptoKey
): Promise<string> {
  const exported = await subtle.exportKey("pkcs8", key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PRIVATE KEY-----\n${exportedAsBase64}\n-----END PRIVATE KEY-----`;
  return pemExported;
}

async function exportPubKey(
  subtle: SubtleCrypto,
  key: CryptoKey
): Promise<string> {
  const exported = await subtle.exportKey("spki", key);
  const exportedAsString = ab2str(exported);
  const exportedAsBase64 = btoa(exportedAsString);
  const pemExported = `-----BEGIN PUBLIC KEY-----\n${exportedAsBase64}\n-----END PUBLIC KEY-----`;
  return pemExported;
}

function test_compact_xgcd() {
  const a: bigint =
    0x8d2eefc58131cb645f8fe2e673288cef5e39f0ee1cab801203f8f1b2e6e7bb6908a52a1ed8528e5c0be6b4829eb23d5e492c46bc839f8ab1b969c35c4b2e029986eccfec40515a4020dc731bd5aba8abe0d1a6dbc32f914a47f9825898c94e518387f56396262a6e9c81f88ad3393131ac74758901192d0549515eac6c573d5e153c9d0573bd889835de0628097d9b36bfb9102b3df40ec6d17f2e22d9db0fcdf1ed909a0c97a0c93f5ea43f6ba857e4ac8e0dfdb31993f0576cc79db6f51126ff3f47eafa2fede71e2b18aa15f2462a3fde32e6cdf3421d5d09ac284f1d78ee55bae7c0532328ff1f8054f1a25328372a3291b6ab6263f8c2a5ac681f5d8709n;

  const b: bigint =
    0xad68e47cd8d6084c71cb5f06499ec2372079674acce203b53128b54b10d829169325de2158f552f5e38224f1c7869f2a776a0a51d03032bfb4b380b893fb2b113f4fb247ccb3c4ff5dcc972f4f04c3cab9bfb7e2f36a8cdeaec1e9bf5c87bbec0da34fcccd57233b21bee87f7938ed51dc81aa24b14044991563fee965fa95751174f5c415643d8abc88da4e70699dc8712695938a4e4878162405f238dd1b9637b67c22f81dbefa38d41d0e791ecff200fad3b42f0a359d857142a1d75bca9d2a8c9e723df821ac083405a9c85a15794009d9935b1e29717677d9c5eeebf6943aced13e76d70d28641a1324b83e47f1709c486bfaed4ff711e5752b27211879n;

  const expected_gcd: bigint =
    0xc27848760eb375e7fd8f910e8284b0c7386fd5e5ddf435faa347bb265b0cec4ba1d9302b9dca69f077d1895abe3f77f7158c7555ccb5fd655fe4258e1285fabadad19d507a99c2761700c34f4088b479affc09177a8a2e1d080401b81036e1ca62c4420e2edfd7e8e34951bc43c1117a1633852d578c6cfbe2ef13becff784abn;

  let { g: g1, u: u1, v: v1 } = xgcd(a, b);
  let { g: g2, u: u2, v: v2 } = xgcd(b, a);
  assert(g1 === expected_gcd);
  assert(g2 === expected_gcd);
  assert(a * u1 + b * v1 === g1);
  assert(a * v2 + b * u2 === g2);
}

async function test_sgx_safari_key() {
  const { privateKey, publicKey } = await sgxCompatKey(crypto.subtle);
  const sk_pem = await exportPrivKey(crypto.subtle, privateKey);
  const pk_pem = await exportPubKey(crypto.subtle, publicKey);

  console.log(`${sk_pem}`);
  console.log(`${pk_pem}`);
}

test_sgx_safari_key();
// test_compact_xgcd();

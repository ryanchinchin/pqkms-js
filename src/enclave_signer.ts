import { OprfClient, OprfClientInitData, OprfError } from "./oprf.js";
import { p384, hashToCurve } from "@noble/curves/p384";
import {
  utf8ToBytes,
  concatBytes,
  hexToBytes,
} from "@noble/curves/abstract/utils";

const isUND = (val: any): boolean => {
  return typeof val === "undefined";
};

type endian_t = "big" | "little";

function assert(val: boolean) {
  if (!val) {
    throw EvalError("Assertion failed");
  }
}

interface ActivityCallback<T> {
  start();
  end(is_success: boolean);
}

function eqArray(arr1: ArrayBuffer, arr2: ArrayBuffer): boolean {
  let a = new Uint8Array(arr1);
  let b = new Uint8Array(arr2);
  let result = arr1.byteLength == arr2.byteLength;
  let min_len =
    arr1.byteLength < arr2.byteLength ? arr1.byteLength : arr2.byteLength;

  for (let i = 0; i < min_len; i++) {
    result &&= a[i] === b[i];
  }
  return result;
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

export const fromHexString = (hexString: string): ArrayBuffer => {
  if (hexString.startsWith("0x") || hexString.startsWith("0X")) {
    hexString = hexString.substring(2);
  }

  if (hexString.length % 2 !== 0) {
    hexString = `0${hexString}`;
  }

  let splits = hexString.match(/.{1,2}/g);
  if (splits) {
    return Uint8Array.from(splits.map((byte) => parseInt(byte, 16)));
  } else {
    return Uint8Array.from([]);
  }
};

export const toHexString = (bytes: ArrayBuffer) =>
  new Uint8Array(bytes).reduce(
    (str, byte) => str + byte.toString(16).padStart(2, "0"),
    ""
  );

export const b64urlEncode = function (buffer: ArrayBuffer) {
  let ab = new Uint8Array(buffer);
  return btoa(Array.from(ab, (b) => String.fromCharCode(b)).join(""))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

export const b64urlDecode = function (
  b64encoded_data: string,
  endian: endian_t = "little"
): ArrayBuffer {
  b64encoded_data = b64encoded_data.replace(/-/g, "+").replace(/_/g, "/");

  var pad = b64encoded_data.length % 4;
  if (pad) {
    if (pad === 1) {
      throw new Error(
        "InvalidLengthError: Input base64url string is the wrong length to determine padding"
      );
    }
    b64encoded_data += new Array(5 - pad).join("=");
  }

  let result = new ArrayBuffer(b64encoded_data.length);
  let dataView = new DataView(result);
  let counter = 0;

  if (endian === "little") {
    [...atob(b64encoded_data)]
      .slice()
      .reverse()
      .forEach((c) => dataView.setUint8(counter++, c.codePointAt(0)));
  } else {
    [...atob(b64encoded_data)].forEach((c) =>
      dataView.setUint8(counter++, c.codePointAt(0))
    );
  }

  return result.slice(0, counter);
};

const extractModulus = async (
  key: CryptoKey,
  endian: endian_t = "little"
): Promise<ArrayBuffer> => {
  assert(key.algorithm.name === "RSASSA-PKCS1-v1_5");
  let pub_json = await EnclaveSigner.hsm().exportKey("jwk", key);
  assert(
    !isUND(pub_json.kty) &&
      !isUND(pub_json.e) &&
      !isUND(pub_json.n) &&
      (pub_json.kty === "RSA" || pub_json.kty === "rsa")
  );
  const pub_exp = b64urlDecode(pub_json.e);
  assert(pub_exp.byteLength == 1 && new DataView(pub_exp).getUint8(0) === 0x3);
  return b64urlDecode(pub_json.n, endian);
};

type Attrs =
  | "DEBUG"
  | "MODE64BIT"
  | "PROVISION_KEY"
  | "EINITTOKEN_KEY"
  | "CET"
  | "KSS"
  | "AEXNOTIFY";

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

interface UserAuthInfo {
  domain_name: string;
  user_name: string;
  auth_algo: string;
  auth_data: string | null;
  salt: string | null;
}

interface UserInfo extends UserAuthInfo {
  mrsigner: string;
  aux_data?: string;
}

interface LoginMessage {
  server_nonce: string;
  challenge: string;
  user_info: UserAuthInfo;
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
  // Server nonce echoed back
  server_nonce: string;

  /// AEAD data echoed back
  aead_data: string;

  /// User's ECDSA public-key as a SEC-1 encoded hex string
  user_pub: string;

  /// PSS RSA Signature over `domain || user_name || user_pub` using
  /// mrsigner enclave signing key
  user_pub_sig: string;

  /// ECDSA signature on user_pub_sig as a proof-of-possession signature
  oprf_pop_sig: string;

  /// Client AEAD Data
  aux_data: string;
}

export class EnclaveSigner {
  static CRYPTO = globalThis.crypto;

  constructor() {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      throw Error(
        "Either this connection is not secure or the browser doesn't support WebCrypto"
      );
    }
  }

  static hsm(): SubtleCrypto {
    return EnclaveSigner.CRYPTO.subtle;
  }

  uuid(): string {
    return EnclaveSigner.CRYPTO.randomUUID();
  }

  async sgx_rsa_key(): Promise<CryptoKeyPair> {
    const publicExponent = new Uint8Array([0x03]);
    const usage: KeyUsage[] = ["sign", "verify"];

    const params: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 3072,
      publicExponent,
      hash: "SHA-256",
    };
    const key = await EnclaveSigner.hsm().generateKey(params, true, usage);
    return key;
  }

  async sign_enclave(
    tbsData: ArrayBuffer,
    signingKey: CryptoKey
  ): Promise<ArrayBuffer> {
    assert(signingKey.type === "private");
    assert(signingKey.algorithm.name === "RSASSA-PKCS1-v1_5");
    return EnclaveSigner.hsm().sign(
      signingKey.algorithm.name,
      signingKey,
      tbsData
    );
  }

  async verify_enclave(
    tbsData: ArrayBuffer,
    signature: ArrayBuffer,
    signingPubKey: CryptoKey
  ): Promise<boolean> {
    assert(signingPubKey.algorithm.name === "RSASSA-PKCS1-v1_5");
    assert(signingPubKey.type === "public");

    return EnclaveSigner.hsm().verify(
      signingPubKey.algorithm.name,
      signingPubKey,
      signature,
      tbsData
    );
  }
}

interface URLVersionedDirectory {
  v0: URLDirectory;
}

interface URLDirectory {
  attestation: string;
  registration_init: string;
  enclave_list: string;
  registration_finish: string;
}

const default_v0_url_directory: URLDirectory = {
  attestation: "/v0/admin/attestation",
  registration_init: "/v0/admin/reg_init",
  enclave_list: "/v0/admin/enclaves",
  registration_finish: "/v0/admin/reg_finish",
};

interface PQKMSResponse<T> {
  code: number;
  message: T;
}

export default class UserRegistrationManager {
  readonly discoveryURL: string;
  readonly baseURL: string;
  readonly oprfClient: OprfClient;
  private oprfClientData: OprfClientInitData | null = null;
  urlDirectory: URLDirectory = null;

  constructor(directoryUrl: string) {
    this.discoveryURL = directoryUrl;
    const url = new URL(this.discoveryURL);
    this.baseURL = url.origin;
    this.oprfClient = new OprfClient(p384, hashToCurve);
  }

  async computeOprfClientData(
    raw_pw: string,
    user_info: UserAuthInfo
  ): Promise<OprfClientInitData> {
    try {
      // Generate random 32-bytes salt
      let salt = EnclaveSigner.CRYPTO.getRandomValues(new Uint8Array(32));

      user_info.salt = toHexString(salt);
      const password = await pwhash(raw_pw, user_info, p384.CURVE.nByteLength);
      this.oprfClientData = this.oprfClient.blind(password);
      return this.oprfClientData;
    } catch (e) {
      if (e instanceof OprfError) {
        if (e.err() == "HashedToInifinity") {
          return this.computeOprfClientData(raw_pw, user_info);
        }
      }
      throw e;
    }
  }

  async parseServerResponse<T>(response: Response): Promise<T> {
    if (response.ok) {
      const resp: PQKMSResponse<T> = await response.json();

      if (resp.code >= 200 && resp.code < 300) {
        return resp.message;
      } else {
        throw new Error(
          `Server returned unexpected response with code: ${resp.code} and message: ${resp.message}`
        );
      }
    } else {
      const err_resp: PQKMSResponse<string> = await response.json();
      throw new Error(`Server error: ${err_resp.code} => ${err_resp.message}`);
    }
  }

  async fetchDirectory(): Promise<URLDirectory> {
    if (this.urlDirectory) {
      return this.urlDirectory;
    }

    try {
      const response = await fetch(this.discoveryURL, {
        mode: "cors",
      });
      // console.log(`Server fetch returned code: ${response.status}`);

      if (response.status >= 200 && response.status < 300) {
        let versioned_directory: URLVersionedDirectory = await response.json();
        this.urlDirectory = versioned_directory.v0;
      } else {
        this.urlDirectory = default_v0_url_directory;
      }
    } catch (e) {
      // console.log(`Error getting enclave directory: ${e}`);
      this.urlDirectory = default_v0_url_directory;
    }
    // console.log(`Using URL directory: ${this.urlDirectory}`);
    return this.urlDirectory;
  }

  async fetchEnclaveList(): Promise<ListModulesServerResponse> {
    let directory = await this.fetchDirectory();
    const fetchUrl = `${this.baseURL}${directory.enclave_list}`;
    // console.log(`Attempting to fetch the list of enclaves from ${fetchUrl}!`);
    const response = await fetch(fetchUrl, {
      mode: "cors",
    });

    const resp =
      await this.parseServerResponse<ListModulesServerResponse>(response);
    return resp;
  }

  async signEnclaves(
    privateKey: CryptoKey,
    publicKey: CryptoKey,
    modulesReq: ListModulesServerResponse
  ): Promise<ClientRegInit> {
    const enclaveSigner = new EnclaveSigner();

    assert(privateKey.type === "private");
    assert(publicKey.type === "public");
    let modulus = await extractModulus(publicKey, "big");

    let result: ClientRegInit = {
      user_info: null,
      server_nonce: null,
      signer_modulus: toHexString(modulus),
      signed_enclaves: [],
    };

    for (let enclave of modulesReq.enclaves) {
      const tbs_data = fromHexString(enclave.tbs_data);
      const sighash = fromHexString(enclave.sighash);
      const expected_sighash = await EnclaveSigner.hsm().digest(
        "SHA-256",
        tbs_data
      );

      let entry: SigStructClientSigned = {
        is_ok: false,
        signature: "",
        enclave_name: enclave.enclave_name,
        config: enclave.config,
      };

      if (!eqArray(sighash, expected_sighash)) {
        entry.signature =
          "Enclave sighash and SHA256(to-be-signed) do not match.";
      } else {
        const sig = await enclaveSigner.sign_enclave(tbs_data, privateKey);
        (entry.is_ok = true), (entry.signature = toHexString(sig));
        result.signed_enclaves.push(entry);
      }
    }

    return result;
  }

  async pssSign(
    domain_name: string,
    email_addr: string,
    login_pub: Uint8Array,
    enclave_keypair: CryptoKeyPair
  ): Promise<Uint8Array> {
    const rsa_priv = await EnclaveSigner.hsm().exportKey(
      "pkcs8",
      enclave_keypair.privateKey
    );

    const pss_signer = await EnclaveSigner.hsm().importKey(
      "pkcs8",
      rsa_priv,
      {
        name: "RSA-PSS",
        hash: "SHA-256",
      },
      false,
      ["sign"]
    );

    let tbs_data = concatBytes(
      utf8ToBytes(domain_name),
      utf8ToBytes(email_addr),
      login_pub
    );

    let pss_signature = await EnclaveSigner.hsm().sign(
      {
        name: "RSA-PSS",
        saltLength: 32,
      },
      pss_signer,
      tbs_data
    );
    return new Uint8Array(pss_signature);
  }

  async regFinalMsg(
    reg_init_msg: RegInitResp,
    login_pub: Uint8Array,
    enclave_keypair: CryptoKeyPair,
    ecdsa_login_key: CryptoKey,
    lockbox_key: CryptoKey
  ): Promise<ClientRegFinish> {
    // console .log(`Computing PSS signature on login pub`);
    const pop_challenge = await this.pssSign(
      reg_init_msg.user_info.domain_name,
      reg_init_msg.user_info.user_name,
      login_pub,
      enclave_keypair
    );

    // console .log(`Computing ECDSA signature as proof-of-possession`);
    const pop_proof = await EnclaveSigner.hsm().sign(
      {
        name: "ECDSA",
        hash: "SHA-384",
      },
      ecdsa_login_key,
      pop_challenge
    );

    let iv = globalThis.crypto.getRandomValues(new Uint8Array(12));

    const wrapped_data = await EnclaveSigner.hsm().wrapKey(
      "pkcs8",
      enclave_keypair.privateKey,
      lockbox_key,
      {
        name: "AES-GCM",
        iv: iv,
      }
    );

    const aux_data = `${b64urlEncode(iv)}.${b64urlEncode(wrapped_data)}`;

    const finish_msg: ClientRegFinish = {
      server_nonce: reg_init_msg.server_nonce,
      aead_data: reg_init_msg.aead_data,
      user_pub: toHexString(login_pub),
      user_pub_sig: toHexString(pop_challenge),
      oprf_pop_sig: toHexString(pop_proof),
      aux_data,
    };

    return finish_msg;
  }

  async regInit(
    raw_pw: string,
    user_info: UserAuthInfo,
    signing_key: CryptoKeyPair
  ): Promise<RegInitResp> {
    const { privateKey: signing_priv, publicKey: mrsigner_pub } = signing_key;

    assert(signing_priv.type === "private");
    assert(mrsigner_pub.type === "public");

    // console .log(`Fetching enclave directory`);
    let directory = await this.fetchDirectory();

    // console .log(`Fetching list of enclaves`);
    let enclaves = await this.fetchEnclaveList();

    // console .log(`Signing enclaves`);
    let signed = await this.signEnclaves(signing_priv, mrsigner_pub, enclaves);

    // console .log(`Computing OPRF Client Data`);
    await this.computeOprfClientData(raw_pw, user_info);

    user_info.auth_data = this.oprfClientData.clientRequestBytes;

    signed.user_info = user_info;
    signed.server_nonce = enclaves.resp_challenge;

    // console .log(`Attempting registration init`);
    let reg_init_url = `${this.baseURL}${directory.registration_init}`;

    let registerResult = await fetch(reg_init_url, {
      method: "POST",
      mode: "cors",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(signed),
    });
    return this.parseServerResponse<RegInitResp>(registerResult);
  }

  async regFinal(
    init_resp: RegInitResp,
    enclave_keypair: CryptoKeyPair
  ): Promise<string> {
    const directory = await this.fetchDirectory();

    // console .log(`Finalizing OPRF session key`);
    const session_key = await this.oprfClient.finalize(
      init_resp.user_info.auth_data,
      this.oprfClientData
    );

    // console .log(`Computing OPRF login key`);
    const { loginKey, publicKey: login_pub } = await this.oprfClient.login_key(
      session_key,
      this.oprfClientData.hashed_password
    );

    // console .log(`Computing lockbox key`);
    const lockbox_key = await this.oprfClient.lockbox_key(
      session_key,
      this.oprfClientData.hashed_password
    );

    const final_msg = await this.regFinalMsg(
      init_resp,
      login_pub,
      enclave_keypair,
      loginKey,
      lockbox_key
    );

    let reg_fini_url = `${this.baseURL}${directory.registration_finish}`;

    const json_data = JSON.stringify(final_msg);

    // console .log(`Sending registration final message:\n${json_data}`);

    let final_result = await fetch(reg_fini_url, {
      method: "POST",
      mode: "cors",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/json",
      },
      body: json_data,
    });

    return this.parseServerResponse<string>(final_result);
  }
}

export function validateDomainStr(domain: string) {
  const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$/g;
  const found = domain.match(regex);
  if (!found) {
    throw new ValidationError(
      "Invalid domain prefix. Must be a valid domain component"
    );
  }
}

export function validateRawPasswordStr(password: string) {
  if (password.length < 8) {
    throw new ValidationError(
      "Invalid password. Must be at least 8 characters"
    );
  }
}

export function validateUsernameStr(user_email: string) {}

export async function pwhash(
  passwd: string,
  user_info: UserAuthInfo,
  key_length_bytes: number
): Promise<Uint8Array> {
  const pwd_pt = passwd + user_info.domain_name + user_info.user_name + passwd;

  const raw_pwd = await EnclaveSigner.hsm().importKey(
    "raw",
    new TextEncoder().encode(pwd_pt),
    {
      name: "PBKDF2",
    },
    false,
    ["deriveBits"]
  );

  let salt = hexToBytes(user_info.salt);

  let key = await EnclaveSigner.hsm().deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 1000000,
      hash: "SHA-256",
    },
    raw_pwd,
    8 * key_length_bytes
  );

  return new Uint8Array(key);
}

export async function register_user(
  domain: string,
  email_addr: string,
  password: string,
  base_url: string,
  crypto_key?: CryptoKeyPair
) {
  validateDomainStr(domain);
  validateRawPasswordStr(password);
  validateUsernameStr(email_addr);

  const key_pair = crypto_key || (await new EnclaveSigner().sgx_rsa_key());

  let user: UserAuthInfo = {
    domain_name: domain,
    user_name: email_addr,
    auth_algo: "OPRF.P384-SHA384",
    auth_data: null,
    salt: null,
  };

  let reg = new UserRegistrationManager(base_url);
  const reg_init_data = await reg.regInit(password, user, key_pair);
  await reg.regFinal(reg_init_data, key_pair);
}

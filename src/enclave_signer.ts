import * as argon2 from "argon2-wasm-esm";
import { OprfClient, OprfClientInitData, OprfError } from "./oprf.js";
import { p384, hashToCurve } from "@noble/curves/p384";

// This is based on OWASP recommendataion from
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
const argon_config = {
  time: 2, // the number of iterations: 2
  mem: 19456, // used memory, in KiB: 19MiB
  parallelism: 1, // desired parallelism
  type: argon2.ArgonType.Argon2di, // or argon2.ArgonType.Argon2i
};

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

interface RegistrationProgressCallback {
  fetchDirectory: ActivityCallback<void> | null;
  keygen: ActivityCallback<CryptoKeyPair> | null;
  sign: ActivityCallback<[SigStructTbsInfo]> | null;
  oprf: ActivityCallback<OprfClientInitData> | null;
  registrationInit: ActivityCallback<void> | null;
  registrationFinal: ActivityCallback<void> | null;
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
    let usage: KeyUsage[] = ["sign", "verify"];

    let params: RsaHashedKeyGenParams = {
      name: "RSASSA-PKCS1-v1_5",
      modulusLength: 3072,
      publicExponent,
      hash: "SHA-256",
    };
    const start_time = performance.now();
    const key = await EnclaveSigner.hsm().generateKey(params, false, usage);
    const end_time = performance.now();
    console.log("Time taken to generate RSA key: ", end_time - start_time);
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

interface URLDirectory {
  enclave_list: string;
  register_domain: string;
}

interface PQKMSResponse {
  code: number;
  message: any;
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
    user_info: RegistrationReqInitMsg
  ): Promise<OprfClientInitData> {
    for (let i = 0; i < 5; i++) {
      let argon_hash = await pwhash(
        user_info.domain_name,
        user_info.email_addr,
        raw_pw,
        i
      );

      try {
        this.oprfClientData = this.oprfClient.blind(argon_hash);
        return this.oprfClientData;
      } catch (e) {
        if (e instanceof OprfError) {
          if (e.err() == "HashedToInifinity") {
            continue;
          }
        }
        throw e;
      }
    }
    throw new Error("Unusable password!");
  }

  async parseServerResponse(response: Response): Promise<any> {
    // let hdrs = new Map(response.headers);
    console.log(
      `Server returned response code: ${response.status} ${response.statusText} with headers:\n ${response.headers}`
    );

    if (response.ok) {
      const resp: PQKMSResponse = await response.json();

      if (resp.code >= 200 && resp.code < 300) {
        return resp.message;
      } else {
        throw new Error(
          `Server returned unexpected response with code: ${resp.code} and message: ${resp.message}`
        );
      }
    } else {
      const err_resp: PQKMSResponse = await response.json();
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
      console.log(`Server fetch returned code: ${response.status}`);

      if (response.status >= 200 && response.status < 300) {
        this.urlDirectory = await response.json();
      } else {
        this.urlDirectory = {
          enclave_list: "/v0/admin/enclaves",
          register_domain: "/v0/admin/register_domain",
        };
      }
    } catch (e) {
      console.log(`Error getting enclave directory: ${e}`);
      this.urlDirectory = {
        enclave_list: "/v0/admin/enclaves",
        register_domain: "/v0/admin/register_domain",
      };
    }
    console.log(`Using URL directory: ${this.urlDirectory}`);
    return this.urlDirectory;
  }

  async fetchEnclaveList(): Promise<ListModulesServerResponse> {
    let directory = await this.fetchDirectory();
    const fetchUrl = `${this.baseURL}${directory.enclave_list}`;
    console.log(`Attempting to fetch the list of enclaves from ${fetchUrl}!`);
    const response = await fetch(fetchUrl, {
      mode: "cors",
    });

    const resp = await this.parseServerResponse(response);
    return resp;
  }

  async signEnclaves(
    enclaveSigningKey: CryptoKeyPair,
    modulesReq: ListModulesServerResponse
  ): Promise<ClientRequestForRegistration> {
    const enclaveSigner = new EnclaveSigner();
    let { privateKey, publicKey } = enclaveSigningKey;

    assert(privateKey.type === "private");
    let modulus = await extractModulus(publicKey, "big");

    let result: ClientRequestForRegistration = {
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

  async registerUser(
    raw_pw: string,
    user_info: RegistrationReqInitMsg,
    progress?: RegistrationProgressCallback
  ) {
    console.log(`Fetching enclave directory`);
    let directory = await this.fetchDirectory();

    console.log(`Fetching list of enclaves`);
    let enclaves = await this.fetchEnclaveList();

    console.log(`Signing enclaves`);
    let signed = await this.signEnclaves(user_info.enclave_key, enclaves);

    console.log(`Computing OPRF Client Data`);
    await this.computeOprfClientData(raw_pw, user_info);

    user_info.oprf_client_data = this.oprfClientData.clientRequestBytes;

    signed.user_info = user_info;
    signed.server_nonce = enclaves.resp_challenge;

    console.log(`Attempting stage-1 of registration`);
    let register_url = `${this.baseURL}${directory.register_domain}`;
    try {
      let registerResult = await fetch(register_url, {
        method: "POST",
        mode: "cors",
        cache: "no-cache",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify(signed),
      });
      let resp = await this.parseServerResponse(registerResult);
      if (resp.code >= 200 && resp.code < 300) {
        return true;
      } else {
        return false;
      }
    } catch (e) {
      return false;
    }
  }
}

export function validate_domain_str(domain: string) {
  const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$/g;
  const found = domain.match(regex);
  if (!found) {
    throw new ValidationError(
      "Invalid domain prefix. Must be a valid domain component"
    );
  }
}

export function validate_raw_password_str(password: string) {
  if (password.length < 8) {
    throw new ValidationError(
      "Invalid password. Must be at least 8 characters"
    );
  }
}

export function validate_username_str(user_email: string) {}

export async function pwhash(
  domain: string,
  username: string,
  passwd: string,
  repeat?: number // Used to avoid hashing to point at infinity
): Promise<Uint8Array> {
  let salt_pt = passwd + domain + username + passwd;

  if (repeat != null) {
    for (let j = 0; j < repeat; j++) {
      salt_pt = `${passwd}${salt_pt}${passwd}`;
    }
  }

  const argon_salt = new TextEncoder().encode(salt_pt);
  const salt = new Uint8Array(
    await EnclaveSigner.hsm().digest("SHA-256", argon_salt)
  );

  const argon_hash = await argon2.hash({
    pass: passwd,
    salt,
    ...argon_config,
  });
  return argon_hash.hash;
}

export async function register_user(
  domain: string,
  email_addr: string,
  password: string,
  base_url: string,
  crypto_key?: CryptoKeyPair
) {
  validate_domain_str(domain);
  validate_raw_password_str(password);
  validate_username_str(email_addr);

  let reg = new UserRegistrationManager(base_url);
  const enclaveKey = crypto_key || (await new EnclaveSigner().sgx_rsa_key());
  let user: RegistrationReqInitMsg = {
    domain_name: domain,
    email_addr: email_addr,
    enclave_key: enclaveKey,
    oprf_client_data: null,
  };

  const registerUser = await reg.registerUser(password, user);
  console.log(`Registration `, registerUser ? "Successful" : "Failed");
}

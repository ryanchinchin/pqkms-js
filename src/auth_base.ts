import { toHexString, hexToBytes } from "./utils.js";
import { OprfClient, OprfClientInitData, OprfError } from "./oprf.js";
import { p384, hashToCurve } from "@noble/curves/p384";

export interface UserAuthInfo {
  domain_name: string;
  user_name: string;
  auth_algo: string;
  auth_data: string | null;
  salt: string | null;
}

export interface UserInfo extends UserAuthInfo {
  mrsigner: string;
  aux_data?: string;
  access_url?: string;
}

export function to_auth_info(user_info: UserInfo): UserAuthInfo {
  const { domain_name, user_name, auth_algo, auth_data, salt } = user_info;
  return {
    domain_name,
    user_name,
    auth_data,
    auth_algo,
    salt,
  };
}

export interface URLVersionedDirectory<T> {
  v0: T;
}

interface PQKMSResponse<T> {
  code: number;
  message: T;
}

export abstract class UserAuthBase {
  readonly discoveryURL: string;
  readonly baseURL: string;
  readonly oprfClient: OprfClient;
  protected oprfClientData: OprfClientInitData | null = null;

  constructor(directoryUrl: string) {
    if (!globalThis.crypto || !globalThis.crypto.subtle) {
      throw Error(
        "Either this connection is not secure or the browser doesn't support WebCrypto"
      );
    }
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
      if (!user_info.salt) {
        user_info.salt = toHexString(
          globalThis.crypto.getRandomValues(new Uint8Array(32))
        );
      }

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
        throw new Error(`${resp.message}`);
      }
    } else {
      const err_resp: PQKMSResponse<string> = await response.json();
      throw new Error(`${JSON.stringify(err_resp)}`);
    }
  }

  abstract fetchDirectory(): Promise<any>;

  async fetchUserInfo(
    user_name: string,
    domain_name?: string,
    auth_algo?: string
  ): Promise<Array<UserInfo>> {
    const directory = await this.fetchDirectory();
    let user_info_url = `${this.discoveryURL}${directory.user_info}?user_name=${user_name}`;

    if (domain_name) {
      user_info_url = `${user_info_url}&domain=${domain_name}`;
    }

    if (auth_algo) {
      user_info_url = `${user_info_url}&domain=${auth_algo}`;
    }

    const response = await fetch(user_info_url, {
      keepalive: true,
      mode: "cors",
      cache: "no-store",
    });

    return this.parseServerResponse<Array<UserInfo>>(response);
  }
}

export async function pwhash(
  passwd: string,
  user_info: UserAuthInfo,
  key_length_bytes: number
): Promise<Uint8Array> {
  const pwd_pt = passwd + user_info.domain_name + user_info.user_name + passwd;

  const raw_pwd = await globalThis.crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(pwd_pt),
    {
      name: "PBKDF2",
    },
    false,
    ["deriveBits"]
  );

  let salt = hexToBytes(user_info.salt!);

  let key = await globalThis.crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: 600000,
      hash: "SHA-256",
    },
    raw_pwd,
    8 * key_length_bytes
  );

  return new Uint8Array(key);
}

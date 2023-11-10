import {
  UserAuthBase,
  URLVersionedDirectory,
  UserAuthInfo,
} from "./auth_base.js";

import {
  InvalidRequest,
  ValidationError,
  AuthenticationFailed,
  assert,
  fromHexString,
  toHexString,
  b64urlDecode,
} from "./utils";

const X_AUTHORIZATION_TOKEN: string = "X-Authorization-PQKMS-Token";

export interface ProjectDirectory {
  attestation: string;
  login_init: string;
  login_finish: string;
  user_info: string;
}

interface LoginMessage {
  server_nonce: string;
  challenge: string;
  user_info: UserAuthInfo;
}

interface LoginFinalResp {
  user_name: string;
  domain: string;
  auth_token: string;
  aux_data?: string;
  not_before: string;
  not_after: string;
}

interface PQKMSResponse<T> {
  code: number;
  message: T;
}

class AuthIO {
  constructor(
    private readonly login_data: LoginFinalResp,
    private readonly lockbox_key?: CryptoKey,
    private readonly subtle?: SubtleCrypto
  ) {
    this.subtle = this.subtle || globalThis.crypto.subtle;
  }

  async fetch<U, T>(
    url: string | URL | Request,
    method: string,
    data?: T,
    headers?: HeadersInit
  ): Promise<U> {
    if (this.login_data.auth_token.length === 0) {
      throw new InvalidRequest("User unauthenticated");
    }

    let hdrs = headers || {};

    hdrs["Authorization"] = `Bearer ${this.login_data.auth_token}`;

    let body = null;

    if (data) {
      hdrs["Content-Type"] = hdrs["Content-Type"] || "application/json";
      body = JSON.stringify(data);
    }

    let response: Response = await fetch(url, {
      method,
      mode: "cors",
      cache: "no-cache",
      keepalive: true,
      headers: hdrs,
      body,
    });

    return this.parse<U>(response);
  }

  private async parse<T>(response: Response): Promise<T> {
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

  async enclaveSigningKey(): Promise<CryptoKey> {
    if (!this.lockbox_key || !this.login_data.aux_data) {
      throw new InvalidRequest("enclave signing key unavailable");
    }
    let values = this.login_data.aux_data!.split(`.`);

    if (values.length !== 2) {
      throw new InvalidRequest("Invalid auxilary data");
    }

    const iv = b64urlDecode(values[0], "big");
    const wrapped_key = b64urlDecode(values[1], "big");

    return this.subtle!.unwrapKey(
      "pkcs8",
      wrapped_key,
      this.lockbox_key!,
      {
        name: "AES-GCM",
        iv: iv,
      },
      {
        name: "RSASSA-PKCS1-v1_5",
        hash: "SHA-256",
      },
      true,
      ["sign"]
    );
  }
}

const default_v0_app_directory: ProjectDirectory = {
  attestation: "/v0/admin/attestation",
  login_init: "/v0/admin/login_init",
  login_finish: "/v0/admin/login_finish",
  user_info: "/v0/admin/user_info",
};

export default class AuthManager extends UserAuthBase {
  protected directory: ProjectDirectory | null = null;

  constructor(directoryUrl: string) {
    super(directoryUrl);
  }

  async loginFinalMsg(
    msg: LoginMessage,
    login_key: CryptoKey
  ): Promise<LoginMessage> {
    let challenge = fromHexString(msg.challenge);
    let signature = await globalThis.crypto.subtle.sign(
      {
        name: "ECDSA",
        hash: "SHA-384",
      },
      login_key,
      challenge
    );
    msg.user_info.auth_data = toHexString(signature);
    return msg;
  }

  async fetchDirectory(): Promise<ProjectDirectory> {
    if (this.directory) {
      return this.directory;
    }

    try {
      const response = await fetch(this.discoveryURL, {
        mode: "cors",
        cache: "no-store",
        keepalive: true,
      });
      // console.log(`Server fetch returned code: ${response.status}`);

      if (response.ok) {
        let versioned_directory: URLVersionedDirectory<ProjectDirectory> =
          await response.json();
        this.directory = versioned_directory.v0;
      } else {
        this.directory = default_v0_app_directory;
      }
    } catch (e) {
      // console.log(`Error getting enclave directory: ${e}`);
      this.directory = default_v0_app_directory;
    }
    // console.log(`Using URL directory: ${this.urlDirectory}`);

    return this.directory!;
  }

  // Compute init request data given input from `loginInit` request
  async loginInit(
    auth_info: UserAuthInfo,
    raw_pw: string
  ): Promise<LoginMessage> {
    // console .log(`Fetching enclave directory`);
    const directory = await this.fetchDirectory();
    let clientData = await this.computeOprfClientData(raw_pw, auth_info);

    auth_info.auth_data = clientData.clientRequestBytes;
    let login_init_url = `${this.baseURL}${directory.login_init}`;

    delete auth_info.salt;

    let registerResult = await fetch(login_init_url, {
      method: "POST",
      mode: "cors",
      cache: "no-store",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(auth_info),
      keepalive: true,
    });
    return this.parseServerResponse<LoginMessage>(registerResult);
  }

  // Compute the final response data given input from `loginInit` request
  async loginFinal(login_init_resp: LoginMessage): Promise<AuthIO> {
    const directory = await this.fetchDirectory();

    // console .log(`Finalizing OPRF session key`);
    const session_key = await this.oprfClient.finalize(
      login_init_resp.user_info.auth_data!,
      this.oprfClientData!
    );

    // console .log(`Computing OPRF login key`);
    const { loginKey } = await this.oprfClient.login_key(
      session_key,
      this.oprfClientData!.hashed_password
    );

    const final_msg = await this.loginFinalMsg(login_init_resp, loginKey);
    const json_data = JSON.stringify(final_msg);

    let login_fini_url = `${this.baseURL}${directory.login_finish}`;

    let final_result: Response = await fetch(login_fini_url, {
      method: "POST",
      mode: "cors",
      cache: "no-cache",
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Request-Headers": X_AUTHORIZATION_TOKEN,
      },
      body: json_data,
    });

    if (final_result.ok) {
      let lockbox_key: CryptoKey | null = null;

      const auth_token = final_result.headers.get(X_AUTHORIZATION_TOKEN);
      const resp = await this.parseServerResponse<LoginFinalResp>(final_result);

      assert(auth_token === resp.auth_token);

      if (resp.aux_data && resp.aux_data.length > 0) {
        lockbox_key = await this.oprfClient.lockbox_key(
          session_key,
          this.oprfClientData!.hashed_password
        );
      }

      return new AuthIO(resp, lockbox_key);
    } else {
      try {
        this.parseServerResponse(final_result);
        throw new ValidationError(
          `Authentication failed with error code: ${final_result.status}`
        );
      } catch (e) {
        throw new AuthenticationFailed(
          `${e.message}`,
          login_init_resp.user_info.user_name,
          login_init_resp.user_info.domain_name
        );
      }
    }
  }
}

export async function login_user(
  domain_name: string,
  user_name: string,
  raw_passwd: string,
  salt: string,
  auth_algo: string,
  access_url: string
): Promise<AuthIO> {
  const auth_manager = new AuthManager(access_url);
  let user_info: UserAuthInfo = {
    domain_name,
    user_name,
    salt,
    auth_algo,
    auth_data: null,
  };

  let login_msg = await auth_manager.loginInit(user_info, raw_passwd);

  return auth_manager.loginFinal(login_msg);
}

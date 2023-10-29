import {
  UserAuthBase,
  URLVersionedDirectory,
  UserAuthInfo,
} from "./auth_base.js";

export interface UserInfo extends UserAuthInfo {
  mrsigner: string;
  aux_data?: string;
}

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

const default_v0_app_directory: ProjectDirectory = {
  attestation: "/v0/admin/attestation",
  login_init: "/v0/admin/login_init",
  login_finish: "/v0/admin/reg_finish",
  user_info: "/v0/admin/user_info",
};

export default class AuthManager extends UserAuthBase {
  protected directory: ProjectDirectory | null = null;

  constructor(directoryUrl: string) {
    super(directoryUrl);
  }

  async fetchDirectory(): Promise<ProjectDirectory> {
    if (this.directory) {
      return this.directory;
    }

    try {
      const response = await fetch(super.discoveryURL, {
        mode: "cors",
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

  async fetchUserInfo(user_name: string): Promise<Array<UserInfo>> {
    const directory = await this.fetchDirectory();
    const user_info_url = `${super.discoveryURL}${
      directory.user_info
    }?user_name=${user_name}`;

    const response = await fetch(user_info_url, {
      mode: "cors",
    });

    return super.parseServerResponse<Array<UserInfo>>(response);
  }

  async loginInit(
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

    user_info.auth_data = this.oprfClientData!.clientRequestBytes;

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
      init_resp.user_info.auth_data!,
      this.oprfClientData!
    );

    // console .log(`Computing OPRF login key`);
    const { loginKey, publicKey: login_pub } = await this.oprfClient.login_key(
      session_key,
      this.oprfClientData!.hashed_password
    );

    // console .log(`Computing lockbox key`);
    const lockbox_key = await this.oprfClient.lockbox_key(
      session_key,
      this.oprfClientData!.hashed_password
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

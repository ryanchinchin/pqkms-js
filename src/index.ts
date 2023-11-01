export interface UserProjectsInfo {
  domain_name: string;
  user_name: string;
  salt: string;
  auth_algo: string;
  mrsigner: string;
  access_url: string;
}

export async function register_user(
  domain: string,
  user_name: string,
  password: string,
  base_url: string,
  crypto_key?: CryptoKeyPair
): Promise<string> {
  const urm = await import("./registration");
  return urm.register_user(domain, user_name, password, base_url, crypto_key);
}

export async function login_user(
  pi: UserProjectsInfo,
  raw_passwd: string
): Promise<boolean> {
  const login = await import("./login");
  const access_url = `https://${pi.access_url}`;
  return login.login_user(
    pi.domain_name,
    pi.user_name,
    raw_passwd,
    pi.salt,
    pi.auth_algo,
    access_url
  );
}

export async function fetch_user_projects(
  registration_url: string,
  user_name: string
): Promise<Array<UserProjectsInfo>> {
  interface HttpResponse<T> {
    code: number;
    message: T;
  }

  let user_info_url = `${registration_url}/v0/admin/user_info?user_name=${user_name}`;
  const response = await fetch(user_info_url, {
    mode: "cors",
    cache: "no-store",
  });

  if (response.ok) {
    const resp: HttpResponse<Array<UserProjectsInfo>> = await response.json();
    return resp.message;
  } else {
    const err_resp: HttpResponse<string> = await response.json();
    throw new Error(`Server error: ${err_resp.code} => ${err_resp.message}`);
  }
}

import {
  fetch_user_projects,
  login_user,
  UserProjectsInfo,
  AuthenticatedInterface,
} from "../lib/index";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

async function validate_login_token(u: UserProjectsInfo, password) {
  console.log(`-----------------`);
  console.log(
    `Loging user: ${u.user_name},  project: ${u.domain_name}, access_url: ${u.access_url}`
  );
  const auth_inf: AuthenticatedInterface = await login_user(u, password);
  const enc_signing_key = await auth_inf.enclaveSigningKey();
  const data: Array<UserProjectsInfo> = await auth_inf.fetch(
    `https://${u.access_url}/v0/admin/user_info?user_name=${u.user_name}`,
    "GET"
  );
  console.log(`${JSON.stringify(data)}`);
  console.log(`-----------------`);
}

interface Credentials {
  name: string;
  pass: string;
}

async function test_login_valid(
  user_list: [Credentials],
  registration_url: string
) {
  let users: Array<UserProjectsInfo> = [];

  for (const u of user_list) {
    let pi = await fetch_user_projects(registration_url, u.name);
    pi.forEach((p) => users.push(p));
  }

  await Promise.all([
    validate_login_token(users[0], "spyder39"),
    // validate_login_token(users[1], "spyder39"),
    //    validate_login_token(users[2], "spyder39"),
    //    validate_login_token(users[3], "spyder39"),
  ]);
}

test_login_valid(
  [
    //    { name: "yogesh.swami@gmail.com", pass: "spyder39" },
    { name: "axelexic@gmail.com", pass: "spyder39" },
    { name: "sumanthakur1976@gmail.com", pass: "spyder39" },
  ],
  "https://registrar.pqkms.dev:8443"
);

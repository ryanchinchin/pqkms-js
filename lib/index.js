export async function register_user(domain, user_name, password, base_url, crypto_key) {
    const urm = await import("./registration");
    return urm.register_user(domain, user_name, password, base_url, crypto_key);
}
export async function login_user(user_projs) {
    const login = await import("./login");
}
export async function fetch_user_projects(registration_url, user_name) {
    let user_info_url = `${registration_url}/v0/admin/user_info?user_name=${user_name}`;
    const response = await fetch(user_info_url, {
        mode: "cors",
        cache: "no-store",
    });
    if (response.ok) {
        const resp = await response.json();
        return resp.message;
    }
    else {
        const err_resp = await response.json();
        throw new Error(`Server error: ${err_resp.code} => ${err_resp.message}`);
    }
}

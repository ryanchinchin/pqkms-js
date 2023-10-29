export async function register_user(domain, email_addr, password, base_url, crypto_key) {
    let reg = await import("./registration");
    return reg.register_user(domain, email_addr, password, base_url, crypto_key);
}

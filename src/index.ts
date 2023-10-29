export async function register_user(
  domain: string,
  email_addr: string,
  password: string,
  base_url: string,
  crypto_key?: CryptoKeyPair
) {
  let reg = await import("./registration");
  return reg.register_user(domain, email_addr, password, base_url, crypto_key);
}

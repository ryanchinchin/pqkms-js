import { assert, toHexString, fromHexString, eqArray, b64urlEncode, concatBytes, utf8ToBytes, ValidationError, } from "./utils.js";
import { extractModulus, EnclaveSigner } from "./enclave_signer.js";
import { UserAuthManager, } from "./login.js";
const default_v0_reg_directory = {
    attestation: "/v0/admin/attestation",
    registration_init: "/v0/admin/reg_init",
    enclave_list: "/v0/admin/enclaves",
    registration_finish: "/v0/admin/reg_finish",
    user_info: "/v0/admin/user_info",
};
export default class UserRegistrationManager extends UserAuthManager {
    constructor(directoryUrl) {
        super(directoryUrl);
    }
    async fetchDirectory() {
        if (this.directory) {
            return this.directory;
        }
        try {
            const response = await fetch(this.discoveryURL, {
                mode: "cors",
            });
            if (response.status >= 200 && response.status < 300) {
                let versioned_directory = await response.json();
                this.directory = versioned_directory.v0;
            }
            else {
                this.directory = default_v0_reg_directory;
            }
        }
        catch (e) {
            this.directory = default_v0_reg_directory;
        }
        return this.directory;
    }
    async fetchEnclaveList() {
        let directory = (await this.fetchDirectory());
        const fetchUrl = `${this.baseURL}${directory.enclave_list}`;
        const response = await fetch(fetchUrl, {
            mode: "cors",
        });
        const resp = await this.parseServerResponse(response);
        return resp;
    }
    async signEnclaves(privateKey, publicKey, modulesReq) {
        const enclaveSigner = new EnclaveSigner();
        assert(privateKey.type === "private");
        assert(publicKey.type === "public");
        let modulus = await extractModulus(publicKey, "big");
        let result = {
            user_info: null,
            server_nonce: null,
            signer_modulus: toHexString(modulus),
            signed_enclaves: [],
        };
        for (let enclave of modulesReq.enclaves) {
            const tbs_data = fromHexString(enclave.tbs_data);
            const sighash = fromHexString(enclave.sighash);
            const expected_sighash = await EnclaveSigner.hsm().digest("SHA-256", tbs_data);
            let entry = {
                is_ok: false,
                signature: "",
                enclave_name: enclave.enclave_name,
                config: enclave.config,
            };
            if (!eqArray(sighash, expected_sighash)) {
                entry.signature =
                    "Enclave sighash and SHA256(to-be-signed) do not match.";
            }
            else {
                const sig = await enclaveSigner.sign_enclave(tbs_data, privateKey);
                (entry.is_ok = true), (entry.signature = toHexString(sig));
                result.signed_enclaves.push(entry);
            }
        }
        return result;
    }
    async pssSign(domain_name, email_addr, login_pub, enclave_keypair) {
        const rsa_priv = await EnclaveSigner.hsm().exportKey("pkcs8", enclave_keypair.privateKey);
        const pss_signer = await EnclaveSigner.hsm().importKey("pkcs8", rsa_priv, {
            name: "RSA-PSS",
            hash: "SHA-256",
        }, false, ["sign"]);
        let tbs_data = concatBytes(utf8ToBytes(domain_name), utf8ToBytes(email_addr), login_pub);
        let pss_signature = await EnclaveSigner.hsm().sign({
            name: "RSA-PSS",
            saltLength: 32,
        }, pss_signer, tbs_data);
        return new Uint8Array(pss_signature);
    }
    async regFinalMsg(reg_init_msg, login_pub, enclave_keypair, ecdsa_login_key, lockbox_key) {
        const pop_challenge = await this.pssSign(reg_init_msg.user_info.domain_name, reg_init_msg.user_info.user_name, login_pub, enclave_keypair);
        const pop_proof = await EnclaveSigner.hsm().sign({
            name: "ECDSA",
            hash: "SHA-384",
        }, ecdsa_login_key, pop_challenge);
        let iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
        const wrapped_data = await EnclaveSigner.hsm().wrapKey("pkcs8", enclave_keypair.privateKey, lockbox_key, {
            name: "AES-GCM",
            iv: iv,
        });
        const aux_data = `${b64urlEncode(iv)}.${b64urlEncode(wrapped_data)}`;
        const finish_msg = {
            server_nonce: reg_init_msg.server_nonce,
            aead_data: reg_init_msg.aead_data,
            user_pub: toHexString(login_pub),
            user_pub_sig: toHexString(pop_challenge),
            oprf_pop_sig: toHexString(pop_proof),
            aux_data,
        };
        return finish_msg;
    }
    async regInit(raw_pw, user_info, signing_key) {
        const { privateKey: signing_priv, publicKey: mrsigner_pub } = signing_key;
        assert(signing_priv.type === "private");
        assert(mrsigner_pub.type === "public");
        let directory = (await this.fetchDirectory());
        let enclaves = await this.fetchEnclaveList();
        let signed = await this.signEnclaves(signing_priv, mrsigner_pub, enclaves);
        await this.computeOprfClientData(raw_pw, user_info);
        user_info.auth_data = this.oprfClientData.clientRequestBytes;
        signed.user_info = user_info;
        signed.server_nonce = enclaves.resp_challenge;
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
        return this.parseServerResponse(registerResult);
    }
    async regFinal(init_resp, enclave_keypair) {
        const directory = (await this.fetchDirectory());
        const session_key = await this.oprfClient.finalize(init_resp.user_info.auth_data, this.oprfClientData);
        const { loginKey, publicKey: login_pub } = await this.oprfClient.login_key(session_key, this.oprfClientData.hashed_password);
        const lockbox_key = await this.oprfClient.lockbox_key(session_key, this.oprfClientData.hashed_password);
        const final_msg = await this.regFinalMsg(init_resp, login_pub, enclave_keypair, loginKey, lockbox_key);
        let reg_fini_url = `${this.baseURL}${directory.registration_finish}`;
        const json_data = JSON.stringify(final_msg);
        let final_result = await fetch(reg_fini_url, {
            method: "POST",
            mode: "cors",
            cache: "no-cache",
            headers: {
                "Content-Type": "application/json",
            },
            body: json_data,
        });
        return this.parseServerResponse(final_result);
    }
}
export function validateDomainStr(domain) {
    const regex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]$/g;
    const found = domain.match(regex);
    if (!found) {
        throw new ValidationError("Invalid domain prefix. Must be a valid domain component");
    }
}
export function validateRawPasswordStr(password) {
    if (password.length < 8) {
        throw new ValidationError("Invalid password. Must be at least 8 characters");
    }
}
export function validateUsernameStr(user_email) { }
export async function register_user(domain, email_addr, password, base_url, crypto_key) {
    validateDomainStr(domain);
    validateRawPasswordStr(password);
    validateUsernameStr(email_addr);
    const key_pair = crypto_key || (await new EnclaveSigner().sgx_rsa_key());
    let user = {
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

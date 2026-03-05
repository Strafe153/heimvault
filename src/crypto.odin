package main

foreign import sodium "system:sodium"

foreign sodium {
    sodium_init :: proc() -> i32 ---
    
    @(private="file")
    randombytes_buf :: proc(buf: rawptr, size: uint) ---

    @(private="file")
    crypto_pwhash :: proc(
        out: ^u8,
        outlen: u64,
        passwd: ^u8,
        passwdlen: u64,
        salt: ^u8,
        opslimit: u64,
        memlimit: uint,
        alg: i32
    ) -> i32 ---

    @(private="file")
    crypto_aead_chacha20poly1305_ietf_encrypt :: proc(
        c: ^u8,
        clen_p: ^u64,
        m: ^u8,
        mlen: u64,
        ad: ^u8,
        adlen: u64,
        nsec: ^u8,
        npub: ^u8,
        k: ^u8
    ) -> i32 ---

    @(private="file")
    crypto_aead_chacha20poly1305_ietf_decrypt :: proc(
        m: ^u8,
        mlen_p: ^u64,
        nsec: ^u8,
        c: ^u8,
        clen: u64,
        ad: ^u8,
        adlen: u64,
        npub: ^u8,
        k: ^u8
    ) -> i32 ---
}

SALT_LEN :: 16
NONCE_LEN :: 12
SALT_NONCE_LEN :: SALT_LEN + NONCE_LEN

generate_salt :: proc() -> []u8 {
    salt, e := make([]u8, SALT_LEN)
    randombytes_buf(&salt[0], SALT_LEN)

    return salt
}

generate_nonce :: proc() -> []u8 {
    nonce := make([]u8, NONCE_LEN)
    randombytes_buf(&nonce[0], NONCE_LEN)
    
    return nonce
}

make_key :: proc(password: []u8, salt: []u8) -> ([]u8, bool) {
    hash := make([]u8, HASH_LEN)
    
    result := crypto_pwhash(
        &hash[0],
        u64(len(hash)),
        &password[0],
        u64(len(password)),
        &salt[0],
        DEFAULT_OPS_LIMIT,
        MB_64,
        CRYPTO_PWHASH_ALG_ARGON2ID13)

    return hash, result == 0
}

encrypt :: proc(value: []u8, key: []u8, nonce: []u8) -> ([]u8, bool) {
    ciphered := make([]u8, len(value) + AEAD_TAG_LEN)

    result := crypto_aead_chacha20poly1305_ietf_encrypt(
        &ciphered[0],
        nil,
        &value[0],
        u64(len(value)),
        nil,
        0,
        nil,
        &nonce[0],
        &key[0]
    )

    return ciphered, result == 0
}

decrypt :: proc(value: []u8, key: []u8, nonce: []u8) -> ([]u8, bool) {
    deciphered := make([]u8, len(value) - AEAD_TAG_LEN)

    result := crypto_aead_chacha20poly1305_ietf_decrypt(
        &deciphered[0],
        nil,
        nil,
        &value[0],
        u64(len(value)),
        nil,
        0,
        &nonce[0],
        &key[0]
    )

    return deciphered, result == 0
}

@(private="file")
DEFAULT_OPS_LIMIT :: 3
@(private="file")
CRYPTO_PWHASH_ALG_ARGON2ID13 :: 2
@(private="file")
HASH_LEN :: 32
@(private="file")
MB_64 :: 64 * 1024 * 1024
@(private="file")
AEAD_TAG_LEN :: 16
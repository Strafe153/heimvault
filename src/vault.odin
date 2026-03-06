package main

import "core:encoding/json"
import "core:os"

VaultEntry :: struct {
    site: string,
    username: string,
    password: string
}

VaultEntryError :: enum {
    None,
    Empty_Site,
    Empty_Username,
    Empty_Password,
    Duplicate_Site,
    Io
}

contstruct_entry :: proc(params: []KeyValuePair) -> (VaultEntry, VaultEntryError) {
    entry := VaultEntry{}

    for param in params {
        switch param.key {
            case "site":
                entry.site = param.value
            case "username":
                entry.username = param.value
            case "password":
                entry.password = param.value
        }
    }

    if entry.site == "" {
        return entry, .Empty_Site
    } else if entry.username == "" {
        return entry, .Empty_Username
    } else if entry.password == "" {
        return entry, .Empty_Password
    }

    return entry, .None
}

Vault :: struct {
    salt: []u8,
    nonce: []u8,
    entries: []u8
}

construct_vault :: proc(salt: []u8, nonce: []u8, entries: []u8) -> Vault {
    return Vault{
        salt,
        nonce,
        entries
    }
}

write_vault :: proc(handle: os.Handle, vault: Vault) -> os.Error {
    os.write(handle, vault.salt) or_return
    os.write(handle, vault.nonce) or_return
    os.write(handle, vault.entries) or_return

    return nil
}

write_vault_without_salt :: proc(handle: os.Handle, vault: Vault) -> os.Error {
    os.seek(handle, SALT_LEN, os.SEEK_SET) or_return
    os.write(handle, vault.nonce) or_return
    os.write(handle, vault.entries) or_return

    return nil
}

read_vault :: proc(handle: os.Handle, size: i64) -> (Vault, os.Error) {
    vault := Vault{}

    if _, err := os.seek(handle, 0, os.SEEK_SET); err != nil {
        return vault, err
    }

    encrypted := make([]u8, size)
    if _, err := os.read_full(handle, encrypted); err != nil {
        return vault, err
    }

    vault.salt = encrypted[:SALT_LEN]
    vault.nonce = encrypted[SALT_LEN:SALT_NONCE_LEN]
    vault.entries = encrypted[SALT_NONCE_LEN:]

    return vault, nil
}

list :: proc(vault: ^Vault, key: []u8) -> (e: []VaultEntry, ok: bool) {
    passwords := read_passwords(vault, key) or_return
    return passwords[:], true
}

clear :: proc(handle: os.Handle, vault: ^Vault) -> bool {
    salt, err := read_vault_salt(handle)
    if err != nil {
        return false
    }

    path := get_config_file_path()
    handle, t_err := open_write_truncate(path)
    if t_err != nil {
        return false
    }

    nonce := generate_nonce()
    vault := construct_vault(salt, nonce, []u8{})

    if err := write_vault(handle, vault); err != nil {
        return false
    }

    return true
}

get_by_site :: proc(site: string, vault: ^Vault, key: []u8) -> (e: VaultEntry, r: bool) {
    passwords := read_passwords(vault, key) or_return

    for p in passwords {
        if p.site == site {
            return p, true
        }
    }

    return VaultEntry{}, false
}

get_by_username :: proc(username: string, vault: ^Vault, key: []u8) -> (e: []VaultEntry, ok: bool) {
    passwords := read_passwords(vault, key) or_return
    entries: [dynamic]VaultEntry

    for p in passwords {
        if p.username == username {
            append(&entries, p)
        }
    }

    return entries[:], true
}

remove_by_site :: proc(site: string, handle: os.Handle, vault: ^Vault, key: []u8) -> bool {
    salt, err := read_vault_salt(handle)
    if err != nil {
        return false
    }

    passwords := read_passwords(vault, key) or_return
    for i in 0..<len(vault.entries) {
        if passwords[i].site == site {
            ordered_remove(&passwords, i)
            break
        }
    }

    serialized, m_err := json.marshal(passwords)
    if m_err != nil {
        return false
    }

    nonce := generate_nonce()
    encrypted := encrypt(serialized, key, nonce) or_return

    path := get_config_file_path()
    handle, t_err := open_write_truncate(path)
    if t_err != nil {
        return false
    }

    vault := construct_vault(salt, nonce, encrypted)
    if err = write_vault(handle, vault); err != nil {
        return false
    }

    return true
}

remove_by_username :: proc(username: string, handle: os.Handle, vault: ^Vault, key: []u8) -> bool {
    salt, err := read_vault_salt(handle)
    if err != nil {
        return false
    }

    passwords := read_passwords(vault, key) or_return
    remaining: [dynamic]VaultEntry

    for p in passwords {
        if p.username != username {
            append(&remaining, p)
        }
    }

    serialized, m_err := json.marshal(remaining)
    if m_err != nil {
        return false
    }

    nonce := generate_nonce()
    encrypted := encrypt(serialized, key, nonce) or_return

    path := get_config_file_path()
    handle, t_err := open_write_truncate(path)
    if t_err != nil {
        return false
    }

    vault := construct_vault(salt, nonce, encrypted)
    if err := write_vault(handle, vault); err != nil {
        return false
    }

    return true
}

new :: proc(pairs: []KeyValuePair, handle: os.Handle, vault: ^Vault, key: []u8) -> VaultEntryError {
    entry := contstruct_entry(pairs) or_return

    passwords, ok := read_passwords(vault, key)
    if !ok {
        return .Io
    }

    for i in passwords {
        if i.site == entry.site {
            return .Duplicate_Site
        }
    }
    
    append(&passwords, entry)

    serialized, m_err := json.marshal(passwords)
    if m_err != nil {
        return .Io
    }

    nonce := generate_nonce()
    encrypted, enc_ok := encrypt(serialized, key, nonce)
    if !enc_ok {
        return .Io
    }

    vault := construct_vault(nil, nonce, encrypted)
    if err := write_vault_without_salt(handle, vault); err != nil {
        return .Io
    }

    return .None
}

@(private="file")
read_passwords :: proc(vault: ^Vault, key: []u8) -> (e: [dynamic]VaultEntry, ok: bool) {
    entries: [dynamic]VaultEntry

    if len(vault.entries) > 0 {
        decrypted := decrypt(vault.entries, key, vault.nonce) or_return

        if err := json.unmarshal(decrypted, &entries); err != nil {
            return nil, false
        }
    }

    return entries, true
}

@(private="file")
read_vault_salt :: proc(handle: os.Handle) -> ([]u8, os.Error) {
    if _, err := os.seek(handle, 0, os.SEEK_SET); err != nil {
        return nil, err
    }

    salt := make([]u8, SALT_LEN)
    if _, err := os.read(handle, salt); err != nil {
        return nil, err
    }

    return salt, nil
}

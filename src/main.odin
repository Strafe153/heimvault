package main

import "core:fmt"
import "core:os"

main :: proc() {
    if len(os.args) < 2 {
        fmt.println("No command provided")
        return
    }

    if sodium_init() == -1 {
        fmt.println("Sodium is required")
        return
    }

    handle, cf_err := prepare_config_file()
    if cf_err != nil {
        fmt.println("Config file could not be created")
        return
    }
    defer os.close(handle)

    password, ok := get_master_password()
    if !ok {
        fmt.println("No master password provided")
        return
    }
    
    path := get_config_file_path()
    file_info, e := os.stat(path)
    if e != nil {
        fmt.println("Failed to read the config file")
        return
    }

    vault, v_err := read_vault(handle, file_info.size)
    if v_err != nil {
        fmt.println("Failed to read vault")
        return
    }

    key, key_ok := make_key(password, vault.salt)
    if !key_ok {
        fmt.println("Failed to create master password hash")
        return
    }

    run_command(handle, &vault, key)
}
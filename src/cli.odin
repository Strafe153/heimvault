package main

import "core:fmt"
import "core:os"
import "core:strings"

KeyValuePair :: struct {
    key: string,
    value: string
}

get_master_password :: proc() -> ([]u8, bool) {
    fmt.print("Provide master password: ")

    // 128 +1 for trailing \n
    buffer := make([]u8, 129)

    len, err := os.read(os.stdin, buffer)
    if err != nil || len < 2 {
        return nil, false
    }

    // -1 for trailing \n
    password := buffer[:len - 1]

    return password, true
}

run_command :: proc(handle: os.Handle, vault: ^Vault, key: []u8) {
    switch os.args[1] {
        case "list":
            run_list(vault, key)
        case "clear":
            run_clear(handle, vault)
        case "get":
            run_get(vault, key)
        case "remove":
            run_remove(handle, vault, key)
        case "new":
            run_new(handle, vault, key)
        case:
            fmt.println("Unknown command")
    }
}

@(private="file")
SITE :: "site"
@(private="file")
USERNAME :: "username"
@(private="file")
USERNAME_STR_LEN :: 10 // Length of "Username: "

@(private="file")
parse_arg :: proc(arg: string) -> (string, string, bool) {
    index := strings.index(arg, "=")
    if index < 0 {
        return "", "", false
    }

    key := strings.trim(arg[:index], " ")
    value := strings.trim(arg[index + 1:], " ")

    return key, value, true
}

@(private="file")
parse_new_args :: proc() -> ([]KeyValuePair, bool) {
    args := os.args[2:]

    parsed := make([]KeyValuePair, len(args))
    i := 0

    for arg in args {
        key, value, ok := parse_arg(arg)

        if !ok {
            return nil, false
        }

        parsed[i] = KeyValuePair{ key, value }
        i += 1
    }

    return parsed, true
}

@(private="file")
parse_entry_selector :: proc() -> (KeyValuePair, bool) {
    pair := KeyValuePair{}

    if len(os.args) != 3 {
        return pair, false
    }

    k, v, ok := parse_arg(os.args[2])
    if !ok {
        return pair, false
    }

    pair.key = k
    pair.value = v

    return pair, true
}

@(private="file")
get_delimiter_length :: proc(entries: []VaultEntry) -> int {
    max_length := 0

    for entry in entries {
        if len(entry.site) > max_length {
            max_length = len(entry.site)
        } else if len(entry.username) > max_length {
            max_length = len(entry.username)
        } else if len(entry.password) > max_length {
            max_length = len(entry.password)
        }
    }

    return max_length + USERNAME_STR_LEN
}

@(private="file")
print :: proc(entries: []VaultEntry) {
    delimiter_length := get_delimiter_length(entries)
    delimiter := strings.repeat("-", delimiter_length)

    if len(entries) > 0 {
        fmt.println(delimiter)

        for &entry in entries {
            fmt.printfln("Site: %s", entry.site)
            fmt.printfln("Username: %s", entry.username)
            fmt.printfln("Password: %s", entry.password)

            fmt.println(delimiter)
        }
    } else {
        fmt.println("No passwords found")
    }
}

@(private="file")
print_incorrect_argument :: proc() {
    fmt.println("Incorrect argument")
}

@(private="file")
run_list :: proc(vault: ^Vault, key: []u8) {
    entries, ok := list(vault, key)
    if !ok {
        fmt.println("Failed to read records. Incorrect password")
        return
    }

    print(entries)
}

@(private="file")
run_clear :: proc(handle: os.Handle, vault: ^Vault) {
    if ok := clear(handle, vault); !ok {
        fmt.println("Failed to clear records")
    }
}

@(private="file")
run_get_by_site :: proc(value: string, vault: ^Vault, key: []u8) {
    entry, ok := get_by_site(value, vault, key)
    if !ok {
        fmt.println("Failed to get a record by a site")
        return
    }

    print([]VaultEntry{entry})
}

@(private="file")
run_get_by_username :: proc(value: string, vault: ^Vault, key: []u8) {
    entries, ok := get_by_username(value, vault, key)
    if  !ok {
        fmt.println("Failed to get records by a username")
        return
    }

    print(entries)
}

@(private="file")
run_get :: proc(vault: ^Vault, key: []u8) {
    kv, ok := parse_entry_selector()
    if !ok {
        print_incorrect_argument()
        return
    }

    switch kv.key {
        case SITE:
            run_get_by_site(kv.value, vault, key)
        case USERNAME:
            run_get_by_username(kv.value, vault, key)
        case:
            print_incorrect_argument()
    }
}

@(private="file")
run_remove_by_site :: proc(
    value: string,
    handle: os.Handle,
    vault: ^Vault,
    key: []u8
) {
    if ok := remove_by_site(value, handle, vault, key); !ok {
        fmt.println("Failed to remove a record by a site")
    }
}

@(private="file")
run_remove_by_username :: proc(
    value: string,
    handle: os.Handle,
    vault: ^Vault,
    key: []u8
) {
    if ok := remove_by_username(value, handle, vault, key); !ok {
        fmt.println("Failed to remove records by a username")
    }
}

@(private="file")
run_remove :: proc(handle: os.Handle, vault: ^Vault, key: []u8) {
    kv, ok := parse_entry_selector()
    if !ok {
        print_incorrect_argument()
        return
    }

    switch kv.key {
        case SITE:
            run_remove_by_site(kv.value, handle, vault, key)
        case USERNAME:
            run_remove_by_username(kv.value, handle, vault, key)
        case:
            print_incorrect_argument()
    }
}

@(private="file")
run_new :: proc(handle: os.Handle, vault: ^Vault, key: []u8) {
    if len(os.args) < 4 {
        fmt.println("Not enough arguments")
        return
    }

    params, ok := parse_new_args()
    if !ok {
        fmt.println("Incorrect arguments")
        return
    }

    err := new(params, handle, vault, key)

    #partial switch err {
        case .Empty_Site:
            fmt.println("Site not provided")
        case .Empty_Username:
            fmt.println("Username not provided")
        case .Empty_Password:
            fmt.println("Password not provided")
        case .Duplicate_Site:
            fmt.println("Duplicate site provided")
        case .Io:
            fmt.println("Error operation on the file")
    }
}
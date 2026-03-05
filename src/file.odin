package main

import "core:os"
import "core:path/filepath"

get_config_file_path :: proc() -> string {
    path := get_share_dir_path()
    conf_path := filepath.join([]string{path, "heimvault"})

    return conf_path
}

prepare_config_file :: proc() -> (h: os.Handle, err: os.Error) {
    path := get_config_file_path()
    handle := open_read_write(path) or_return

    file_info := os.stat(path) or_return

    if file_info.size == 0 {
        salt := generate_salt()
        os.write(handle, salt) or_return

        nonce := generate_nonce()
        os.write(handle, nonce) or_return
    }

    return handle, nil
}

open_write_truncate :: proc(path: string) -> (os.Handle, os.Error) {
    return os.open(path, os.O_WRONLY | os.O_TRUNC);
}

@(private="file")
READ_WRITE_MODE :: 0o600

@(private="file")
get_home_dir_path :: proc() -> string {
    home := os.get_env("XDG_DATA_HOME")

    if home == "" {
        home = os.get_env("HOME")
    }

    return home
}

@(private="file")
get_share_dir_path :: proc() -> string {
    home_dir := get_home_dir_path()

    return filepath.join([]string{home_dir, ".local", "share"})
}

@(private)
open_read_write :: proc(path: string) -> (os.Handle, os.Error) {
    return os.open(path, os.O_CREATE | os.O_RDWR, READ_WRITE_MODE)
}
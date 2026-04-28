module tox

import os
import time
import encoding.hex

#flag -ltoxcore
#include <tox/tox.h>

pub type Options = C.Tox_Options
pub struct C.Tox_Options {
    pub:
    ipv6_enabled bool
    udp_enabled bool
    local_discovery_enabled bool
    dht_announcements_enabled bool

    proxy_type  int
    proxy_host  charptr
    proxy_port  u16
    start_port  u16
    end_port    u16
    tcp_port    u16

    hole_punching_enabled bool
    savedata_type SavedataType
    savedata_data byteptr = nil
    savedata_length usize

    log_callback voidptr
    log_user_data voidptr

    experimental_thread_safety bool
    experimental_groups_persistence bool
    experimental_disable_dns bool
    experimental_owned_data bool
    owned_savedata_data bool
}


fn C.tox_options_new(voidptr) &Options
pub fn Options.new() &Options {
    errcode := 0
    return C.tox_options_new(&errcode)
}

fn C.tox_options_free(voidptr)
pub fn (opt &Options) freec() {
    C.tox_options_free(opt)
}

pub fn (opt &Options) load_savedata(file string) ! {
    ba := os.read_bytes(file) !
    opt.savedata_data = ba.data
    opt.savedata_length = usize(ba.len)
    opt.savedata_type = .tox_save
}

pub type Tox = C.Tox
pub struct C.Tox {}

pub fn C.tox_new(...voidptr) &Tox

// opt nilable for default
pub fn new(opt &Options) &Tox {
    errcode := 0

    if opt == nil { opt = Options.new() }
    rv := C.tox_new(opt, &errcode)
    assert errcode == 0
    return rv
}

pub fn C.tox_kill(&Tox)

pub fn (t &Tox) kill() { C.tox_kill(t) }

pub fn C.tox_get_savedata_size(voidptr) usize
pub fn C.tox_get_savedata(...voidptr)

pub fn (t &Tox) save_savedata(file string) ! {
    sz := C.tox_get_savedata_size(t)
    data := []u8{len:int(sz)}
    C.tox_get_savedata(t, &data[0])

    os.write_bytes(file+".new", data) !
    if os.exists(file) { os.rm(file) ! }
    os.rename(file+".new", file) !
}

pub fn C.tox_bootstrap(...voidptr) bool
pub fn C.tox_err_bootstrap_to_string(int) charptr

pub fn (t &Tox) bootstrap(host string, port u16, pubkey string) ! {
    errcode := 0
    binkey := hex.decode(pubkey) !
    ok := C.tox_bootstrap(t, host.str, port, &binkey[0], &errcode)
    if ok { return }

    errmsgc := C.tox_err_bootstrap_to_string(errcode)
    return errorwc(tos_clone(errmsgc), errcode)
}

pub fn C.tox_add_tcp_relay(...voidptr) bool

pub fn (t &Tox) add_tcp_relay(host string, port u16, pubkey string) ! {
    errcode := 0
    binkey := hex.decode(pubkey) !
    ok := C.tox_add_tcp_relay(t, host.str, port, &binkey[0], &errcode)
    if ok { return }

    errmsgc := C.tox_err_bootstrap_to_string(errcode)
    return errorwc(tos_clone(errmsgc), errcode)
}

pub fn C.tox_iteration_interval(voidptr) u32
pub fn C.tox_iterate(...voidptr)

pub fn (t &Tox) iteration_interval() u32 {
    return C.tox_iteration_interval(t)
}

pub fn (t &Tox) iterate() {
    C.tox_iterate(t, nil)
}

pub fn C.tox_self_get_connection_status(&Tox) ConnType

pub fn (t &Tox) self_conn_status() ConnType {
    rv := C.tox_self_get_connection_status(t)
    return rv
}

pub fn (t &Tox) self_user_status() UserStatus {
    return .none
}

pub fn (t &Tox) self_status_text() string {
    return ''
}

pub fn C.tox_self_get_address(...voidptr)

pub fn (t &Tox) self_address() Address {
    buf := []u8{len:C.TOX_ADDRESS_SIZE}
    C.tox_self_get_address(t, buf.data)
    return Address.fromc(buf)
}

//////
pub type Address = string
pub type PublicKey = string
pub type SecretKey = string
pub type DhtId = string
pub type FileId = string

pub enum SavedataType {
    none = C.TOX_SAVEDATA_TYPE_NONE
    tox_save = C.TOX_SAVEDATA_TYPE_TOX_SAVE
    secret_key = C.TOX_SAVEDATA_TYPE_SECRET_KEY
}

pub enum UserStatus {
    none  = C.TOX_USER_STATUS_NONE
    away  = C.TOX_USER_STATUS_AWAY
    busy  = C.TOX_USER_STATUS_BUSY
}

pub enum ConnType {
    none  = C.TOX_CONNECTION_NONE
    tcp   = C.TOX_CONNECTION_TCP
    udp   = C.TOX_CONNECTION_UDP
}

pub fn Address.fromc(v []u8) Address {
    assert v.len == C.TOX_ADDRESS_SIZE
    str := hex.encode(v)
    assert str.len == 2*C.TOX_ADDRESS_SIZE
    return str.to_upper()
}
pub fn (addr Address) toc() []u8 {
    ba := hex.decode(addr) or { panic(err) }
    assert addr.len == 2*C.TOX_ADDRESS_SIZE
    assert ba.len == C.TOX_ADDRESS_SIZE
    return ba
}

////// callback

// const cbfns = map[&Tox]&Callbacks{}
const cbfns = &Callbacks{}

pub struct Callbacks {
    pub:
    friend_requests []voidptr
    friend_messages []voidptr
    group_messages []voidptr

    // private
    dht_nodes_resps []voidptr
}

fn on_friend_request(t &Tox) {
    for _, cbfn in cbfns.friend_requests {
    }
}

pub fn (t &Tox) on_friend_request(cbfn voidptr) {
    assert cbfn != nil

    cbfns.friend_requests << cbfn
    if cbfns.friend_requests.len > 1 {
        return
    }
    C.tox_callback_friend_request(t, on_friend_request)
}
fn C.tox_callback_friend_request(...voidptr)

fn on_friend_message(t &Tox) {
    for _, cbfn in cbfns.friend_messages {
    }
}

pub fn (t &Tox) on_friend_message(cbfn voidptr) {
    assert cbfn != nil
    cbfns.friend_messages << cbfn
    if cbfns.friend_messages.len > 1 {
        return
    }
    C.tox_callback_friend_message(t, on_friend_message)
}
fn C.tox_callback_friend_message(...voidptr)

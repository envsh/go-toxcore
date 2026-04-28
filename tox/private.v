module tox


// #include <tox/tox_private.h>

pub fn (t &Tox) on_dht_nodes_response(cbfn voidptr) {
    cbfns.dht_nodes_resps << cbfn
    if cbfns.dht_nodes_resps.len > 1 {
        return
    }
    c99 {
        // extern void tox_callback_dht_nodes_response(void*, void*);
        tox_callback_dht_nodes_response(t, cbfn);
    }
}

pub fn (t &Tox) group_peer_ip(grpno GroupNumber, peer_id u32) !string {
    errcode := 0
    bv := false
    buf := []u8{cap: 128}
    bufp := buf.data
    c99 {
        // extern bool tox_group_peer_get_ip_address(void*, int, int, uint8_t*, int*);
        bv = tox_group_peer_get_ip_address(t, grpno, peer_id, bufp, &errcode)
    }

    if errcode != 0 {
        errmsgc := C.tox_err_group_peer_query_to_string(errcode)
        return errorwc(errmsgc.tosref(), errcode)
    }
    return charptr(bufp).tosref()
}

pub fn (t &Tox) tox_dht_send_nodes_request(pubkey string, ip string, port u16, target_pubkey string) ! {
    errcode := 0
    errmsgc := charptr(nil)
    bv := false
    c99 {
        bv = tox_dht_send_nodes_request(t, &errcode);
    }

    if errcode != 0 {
        return errorwc(@FN, errcode)
    }
}

pub fn (t &Tox) dht_num_closest() u16 {
    c99 {
        return tox_dht_get_num_closelist(t);
    }
    return 0
}

pub fn (t &Tox) dht_num_closelist_announce_capable() u16 {
    c99 {
        return tox_dht_get_num_closelist_announce_capable(t);
    }
    return 0
}

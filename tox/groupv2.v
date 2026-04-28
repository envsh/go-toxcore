module tox

// tox_group_* API

pub type GroupNumber = u32
pub type PeerNumber = u32
pub type MessageId = u32

fn C.tox_group_new(...voidptr) GroupNumber
fn C.tox_group_join(...voidptr) GroupNumber
fn C.tox_group_leave(...voidptr) bool
fn C.tox_group_send_message(...voidptr) MessageId
fn C.tox_err_group_peer_query_to_string(...voidptr) charptr

pub fn (t &Tox) group_new() !GroupNumber {
    return 0
}

pub fn (t &Tox) group_join() !GroupNumber {
    return 0
}

pub fn (t &Tox) group_leave() ! {

}

pub fn (t &Tox) group_send_message() ! {

}


fn on_group_message(t &Tox) {
    for _, cbfn in cbfns.group_messages {
    }
}

pub fn (t &Tox) on_group_message(cbfn voidptr) {
    assert cbfn != nil
    cbfns.group_messages << cbfn
    if cbfns.group_messages.len > 1 {
        return
    }
    C.tox_callback_group_message(t, on_group_message)
}
fn C.tox_callback_group_message(...voidptr)

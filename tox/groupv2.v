module tox

// tox_group_* API

pub type GroupNumber = u32
pub type PeerNumber = u32
pub type MessageId = u32
pub type GroupChatId = string

pub type PeerId = string | u32 | PeerNumber
pub type GroupId = string | u32 | GroupNumber

fn C.tox_group_new(...voidptr) GroupNumber
fn C.tox_group_join(...voidptr) GroupNumber
fn C.tox_group_leave(...voidptr) bool
fn C.tox_group_send_message(...voidptr) MessageId
fn C.tox_err_group_peer_query_to_string(...voidptr) charptr

pub fn (t &Tox) group_new() !GroupNumber {
    return 0
}

pub fn (t &Tox) group_join(chat_id string) !GroupNumber {
    errcode := 0
    fnum := u32(0)
    errmsgc := charptr(0)
    addrc := Address(chat_id).toc()
    c99 {
        fnum = tox_group_join(t, addrc.str, 0, 0, &errcode);
        errmsgc = tox_err_group_join_to_string(errcode);
    }
    if errcode == 0 { return fnum }

    return errorwc(errmsgc.tosref(), errcode)
}

pub fn (t &Tox) group_leave(gid GroupId) ! {
    gnum := gid.tonum(t) !
    errcode := 0
    errmsgc := charptr(0)
    c99 {
        fnum = tox_group_leave(t, gnum, &errcode);
        errmsgc = tox_err_group_leave_to_string(errcode);
    }
    if errcode == 0 { return }

    return errorwc(errmsgc.tosref(), errcode)
}

pub fn (t &Tox) group_send_message(gid GroupId, msg string) ! {
    gnum := gid.tonum(t) !
    errcode := 0
    errmsgc := charptr(0)
    c99 {
        fnum = tox_group_send_message(t, gnum, 0, msg.str, msg.len, &errcode);
        errmsgc = tox_err_group_send_message_to_string(errcode);
    }
    if errcode == 0 { return }

    return errorwc(errmsgc.tosref(), errcode)
}

pub fn (fid GroupId) tonum(t &Tox) !GroupNumber {
    fnum := u32(0)
    match fid {
        GroupNumber { fnum = fid }
        u32 { fnum = fid }
        string {
            // fnum = t.friend_bypk(fid) !
            assert false, 'todo'
        }
    }
    return fnum
}

///////////

fn on_group_message(t &Tox, gnum u32, pnum u32, msgty int, msg charptr, len usize, msgid u32, cbval voidptr) {
    dump(@FN)
    ba := $embed_file("core.v")
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

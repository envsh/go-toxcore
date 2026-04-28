
import os
import time

import tox
import bsdata


fn test_1() {
    opt := tox.Options.new()
    // dump(opt)
    t := tox.new(opt)
    t.iterate()
    t.kill()
}

fn test_2() {
    opt := tox.Options.new()
    // dump(opt)
    if os.exists("mytox.data") {
        opt.load_savedata("mytox.data") or { panic(err) }
        dump(opt.savedata_length)
    }

    t := tox.new(opt)
    t.iterate()

    x := t.self_address()
    dump(x)
    b := x.toc()
    assert b.len == x.len/2
    x2 := tox.Address.fromc(b)
    assert x2 == x

    t.save_savedata("mytox.data") or { panic(err) }

    t.kill()
}

fn test_bootstrap() {
    t := tox.new(nil)
    n := bsdata.bsnodes[0]
    dump('booting $n')
    t.bootstrap(n.host, n.ports[0], n.pubkey) or { panic(err) }
    t.add_tcp_relay(n.host, n.ports[0], n.pubkey) or { panic(err) }

    // online test
    for i in 0..200 {
        t.iterate()
        // dump(t.self_conn_status())
        if t.self_conn_status() != .none {
            break
        }
        time.sleep(53*time.millisecond)
    }
    myst := t.self_conn_status()
    dump('bootstrap state ${myst}')
}

package tox

import (
	"log"
	"testing"
	"time"
)

// issue #6
func TestIssue6(t *testing.T) {
	opts := NewToxOptions()
	opts.ThreadSafe = true
	opts.Tcp_port = 34567
	_t1, err := NewTox(opts)
	if err != nil {
		t.Fatal(err)
	}
	defer _t1.Kill()

	log.Println(_t1)
	go func() {
		for {
			_t1.Iterate()
			time.Sleep(300 * time.Millisecond)
		}
	}()

	opts2 := NewToxOptions()
	opts2.ThreadSafe = true
	opts2.Tcp_port = 34568
	_t2, err := NewTox(opts2)
	if err != nil {
		t.Fatal(err)
	}
	defer _t2.Kill()

	log.Println(_t2)
	_t2.CallbackGroupInviteAdd(func(_ *Tox, friendNumber uint32, itype uint8, data string, userData interface{}) {
		log.Println(friendNumber, itype)
	}, nil)
	go func() {
		for {
			_t2.Iterate()
			time.Sleep(300 * time.Millisecond)
		}
	}()

	waitcond(func() bool { return _t1.IsConnected() > 0 }, 100)
	waitcond(func() bool { return _t2.IsConnected() > 0 }, 100)
	log.Println("both connected")

	gid := _t1.AddAVGroupChat()
	// ok, err := _t1.DelGroupChat(gid)
	// log.Println(ok, err)
	log.Println(gid)

	time.Sleep(5 * time.Second)
}

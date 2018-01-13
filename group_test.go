package tox

import (
	"log"
	"testing"
	"time"
)

// issue #6
func TestIssue6(t *testing.T) {
	testRunning := true

	opts1 := NewToxOptions()
	opts1.ThreadSafe = true
	opts1.Tcp_port = 34567
	tox1, err := NewTox(opts1)
	if err != nil {
		t.Fatal(err)
	}
	defer tox1.Kill()

	go func() {
		for testRunning {
			tox1.Iterate()
			time.Sleep(300 * time.Millisecond)
		}
	}()

	opts2 := NewToxOptions()
	opts2.ThreadSafe = true
	opts2.Tcp_port = 34568
	tox2, err := NewTox(opts2)
	if err != nil {
		t.Fatal(err)
	}
	defer tox2.Kill()

	tox2.CallbackGroupInviteAdd(func(_ *Tox, friendNumber uint32, itype uint8, data string, userData interface{}) {
		log.Println(friendNumber, itype)
	}, nil)
	go func() {
		for testRunning {
			tox2.Iterate()
			time.Sleep(300 * time.Millisecond)
		}
	}()

	waitcond(func() bool { return tox1.IsConnected() > 0 }, 100)
	waitcond(func() bool { return tox2.IsConnected() > 0 }, 100)

	gid := tox1.AddAVGroupChat()
	// ok, err := _t1.DelGroupChat(gid)
	// log.Println(ok, err)
	t.Log(gid)

	time.Sleep(5 * time.Second)

	testRunning = false
}

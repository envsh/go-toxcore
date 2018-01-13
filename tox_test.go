package tox

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"log"
	"reflect"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// `go test -v -run Covers` will show untested functions
// TODO boundary value testing

var bsnodes = []string{
	"biribiri.org", "33445", "F404ABAA1C99A9D37D61AB54898F56793E1DEF8BD46B1038B9D822E8460FAB67",
	"178.62.250.138", "33445", "788236D34978D1D5BD822F0A5BEBD2C53C64CC31CD3149350EE27D4D9A2F9B6B",
	"198.98.51.198", "33445", "1D5A5F2F5D6233058BF0259B09622FB40B482E4FA0931EB8FD3AB8E7BF7DAF6F",
}

func init() {
	log.SetFlags(log.Flags() | log.Lshortfile)
}

func TestCreate(t *testing.T) {
	t.Run("no options", func(t *testing.T) {
		tox, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}
		tox.Kill()
	})
	t.Run("default options", func(t *testing.T) {
		opts := NewToxOptions()
		tox, err := NewTox(opts)
		if err != nil {
			t.Error(err)
		}
		tox.Kill()
	})
	t.Run("tcp options", func(t *testing.T) {
		opts := NewToxOptions()
		opts.Tcp_port = 34567
		tox, err := NewTox(opts)
		if err != nil {
			t.Error(err)
		}
		tox.Kill()
	})
	t.Run("tcp conflict", func(t *testing.T) {
		opts := NewToxOptions()
		opts.Tcp_port = 34567
		tox1, err1 := NewTox(opts)
		_, err2 := NewTox(opts)
		if err1 != nil || err2 == nil {
			t.Errorf("should [non-nil, nil], got [%v, %v]", err1, err2)
		}
		tox1.Kill()
	})
	t.Run("save profile", func(t *testing.T) {
		tox, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}

		sz := tox.GetSavedataSize()
		dat := tox.GetSavedata()
		if sz <= 0 || dat == nil || len(dat) != int(sz) {
			t.Error("cannot zero")
		}
		tox.Kill()
	})
	t.Run("load profile", func(t *testing.T) {
		tox1, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}

		dat := tox1.GetSavedata()
		tox1.Kill()

		opts := NewToxOptions()
		opts.Savedata_data = dat
		opts.Savedata_type = SAVEDATA_TYPE_TOX_SAVE

		tox2, err := NewTox(opts)
		if err != nil {
			t.Error(err)
		}

		dat2 := tox2.GetSavedata()

		if bytes.Compare(dat, dat2) != 0 {
			t.Error("must ==")
		}
		tox2.Kill()
	})
	t.Run("load error profile", func(t *testing.T) {
		tox1, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}

		dat := tox1.GetSavedata()
		tox1.Kill()

		opts := NewToxOptions()
		opts.Savedata_data = append([]byte("set-broken"), dat...)
		opts.Savedata_type = SAVEDATA_TYPE_TOX_SAVE
		tox2, err := NewTox(opts)
		if err == nil {
			t.Errorf("broken profile loaded")
		}
		tox2.Kill()
	})
	t.Run("load seckey", func(t *testing.T) {
		tox1, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}

		addr := tox1.SelfGetAddress()
		seckey := tox1.SelfGetSecretKey()
		tox1.Kill()

		opts := NewToxOptions()
		opts.Savedata_type = SAVEDATA_TYPE_SECRET_KEY
		binsk, _ := hex.DecodeString(seckey)
		opts.Savedata_data = binsk
		tox2, err := NewTox(opts)
		if err != nil {
			t.Error(err)
		}

		if tox2.SelfGetSecretKey() != seckey {
			t.Error("must =")
		}
		if tox2.SelfGetAddress()[0:PUBLIC_KEY_SIZE*2] != addr[0:PUBLIC_KEY_SIZE*2] {
			t.Error("must =", tox2.SelfGetAddress(), addr)
		}
		tox2.Kill()
	})
	t.Run("destroy", func(t *testing.T) {
		tox, err := NewTox(nil)
		if err != nil {
			t.Error(err)
		}

		tox.Kill()
		if tox.toxcore != nil {
			t.Error("must nil")
		}
	})
}

func TestBase(t *testing.T) {
	tox, err := NewTox(nil)
	if err != nil {
		t.Error(err)
	}
	defer tox.Kill()

	t.Run("name", func(t *testing.T) {
		if tox.SelfGetName() != "" {
			t.Error("must empty")
		}
		if tox.SelfGetNameSize() != 0 {
			t.Error("must zero")
		}
		tname := "test name"
		if err := tox.SelfSetName(tname); err != nil {
			t.Error(err)
		}
		if size := tox.SelfGetNameSize(); size != len(tname) {
			t.Error("must =", size, len(tname))
		}
		tname = strings.Repeat("n", MAX_NAME_LENGTH)
		if err := tox.SelfSetName(tname); err != nil {
			t.Error(err)
		}
		tname = strings.Repeat("n", MAX_NAME_LENGTH+1)
		if err := tox.SelfSetName(tname); err == nil {
			t.Error("must failed", err)
		}
	})
	t.Run("local status", func(t *testing.T) {
		if tox.SelfGetStatusMessageSize() != 0 {
			t.Error("must zero")
		}
		if stm, err := tox.SelfGetStatusMessage(); err != nil || len(stm) != 0 {
			t.Error("must empty", stm, err)
		}
		tmsg := "test status msg"
		if ok, err := tox.SelfSetStatusMessage(tmsg); !ok || err != nil {
			t.Error("must ok", err)
		}
		if stm, err := tox.SelfGetStatusMessage(); err != nil || stm != tmsg {
			t.Error("must =", stm, err)
		}
		tmsg = strings.Repeat("s", MAX_STATUS_MESSAGE_LENGTH)
		if ok, err := tox.SelfSetStatusMessage(tmsg); !ok || err != nil {
			t.Error("must ok", err)
		}
		tmsg = strings.Repeat("s", MAX_STATUS_MESSAGE_LENGTH+1)
		if ok, err := tox.SelfSetStatusMessage(tmsg); ok || err == nil {
			t.Error("must failed", err)
		}
		if tox.SelfGetConnectionStatus() != CONNECTION_NONE {
			t.Error("must none")
		}
	})
	t.Run("address/pubkey", func(t *testing.T) {
		addr := tox.SelfGetAddress()
		if len(addr) != ADDRESS_SIZE*2 {
			t.Error("size")
		}
		pubkey := tox.SelfGetPublicKey()
		if len(pubkey) != PUBLIC_KEY_SIZE*2 {
			t.Error("size")
		}
		if addr[0:len(pubkey)] != pubkey {
			t.Error(addr)
		}
	})
	t.Run("seckey", func(t *testing.T) {
		seckey := tox.SelfGetSecretKey()
		if len(seckey) != SECRET_KEY_SIZE*2 {
			t.Error("size")
		}
	})
	t.Run("nospam", func(t *testing.T) {
	})
}

func TestBootstrap(t *testing.T) {
	tox, err := NewTox(nil)
	if err != nil {
		t.Error(err)
	}
	defer tox.Kill()
	port, _ := strconv.Atoi(bsnodes[1])

	t.Run("success", func(t *testing.T) {
		if ok, err := tox.Bootstrap(bsnodes[0], uint16(port), bsnodes[2]); !ok || err != nil {
			t.Error("must ok", ok, err)
		}
	})
	t.Run("failed", func(t *testing.T) {
		brkey := bsnodes[2]
		brkey = "XYZAB" + bsnodes[2][3:]
		if ok, err := tox.Bootstrap(bsnodes[0], uint16(port), brkey); ok || err == nil {
			t.Error("must failed", ok, err)
		}
		if ok, err := tox.Bootstrap("a.b.c.d", uint16(port), bsnodes[2]); ok || err == nil {
			t.Error("must failed", ok, err)
		}
	})
	t.Run("relay", func(t *testing.T) {
		if ok, err := tox.AddTcpRelay(bsnodes[0], uint16(port), bsnodes[2]); !ok || err != nil {
			t.Error("must ok", ok, err)
		}
		if ok, err := tox.AddTcpRelay("a.b.c.d", uint16(port), bsnodes[2]); ok || err == nil {
			t.Error("must failed", ok, err)
		}
	})
}

type MiniTox struct {
	t      *Tox
	stopch chan struct{}
}

func NewMiniTox() *MiniTox {
	this := &MiniTox{}
	tox, _ := NewTox(nil)
	this.t = tox
	this.stopch = make(chan struct{}, 0)
	return this
}

func (this *MiniTox) Iterate() {
	tickch := time.Tick(100 * time.Millisecond)
	for {
		select {
		case <-tickch:
			this.t.Iterate()
		case <-this.stopch:
			return
		}
	}
}

func (this *MiniTox) bootstrap() {
	for idx := 0; idx < len(bsnodes)/3; idx++ {
		port, err := strconv.Atoi(bsnodes[1+idx*3])
		_, err = this.t.Bootstrap(bsnodes[0+idx*3], uint16(port), bsnodes[2+idx*3])
		if err != nil {
			// TODO: handle error
		}
		_, err = this.t.AddTcpRelay(bsnodes[0+idx*3], uint16(port), bsnodes[2+idx*3])
		if err != nil {
			// TODO: handle error
		}
	}
}

func (this *MiniTox) stop() {
	this.stopch <- struct{}{}
}

var err error

func waitcond(cond func() bool, timeout int) {
	// TODO might infinite loop
	btime := time.Now()
	cnter := 0
	for {
		if cond() {
			// print("\n")
			return
		}

		etime := time.Now()
		dtime := etime.Sub(btime)
		if timeout > 0 && int(dtime.Seconds()) > timeout {
			return // timeout
		}

		if cnter%15 == 0 {
			// print(".")
		}
		cnter += 1
		time.Sleep(51 * time.Millisecond)
	}
}

// login udp / login tcp
func TestLogin(t *testing.T) {
	t.Run("connect", func(t *testing.T) {
		tox := NewMiniTox()
		defer tox.t.Kill()
		tox.bootstrap()
		waitcond(func() bool {
			if tox.t.IterationInterval() == 0 {
				t.Error("why")
			}
			tox.t.Iterate()
			if tox.t.SelfGetConnectionStatus() > CONNECTION_NONE {
				return true
			}
			return false
		}, 60)
		if tox.t.SelfGetConnectionStatus() == CONNECTION_NONE {
			t.Error("maybe iterate not use")
		}
	})
}

func TestFriend(t *testing.T) {
	t.Run("add friend", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			_, err := t1.t.FriendAddNorequest(friendId)
			if err != nil {
				t.Error()
			}
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)
		friendNumber, err := t2.t.FriendAdd(t1.t.SelfGetAddress(), "hoho")
		if err != nil {
			t.Error(err, friendNumber)
		}
		_, err = t2.t.FriendAdd(t1.t.SelfGetAddress(), "hehe")
		if err == nil {
			t.Error(err)
		}
		if t2.t.SelfGetFriendListSize() != 1 {
			t.Error("friend size not match")
		}
		lst := t2.t.SelfGetFriendList()
		if len(lst) != 1 {
			t.Error("friend list not match")
		}

		friendNumber2, err := t2.t.FriendByPublicKey(t1.t.SelfGetAddress())
		if err != nil {
			t.Error(err)
		}
		if friendNumber2 != friendNumber {
			t.Error("friend number not match")
		}
		pubkey, err := t2.t.FriendGetPublicKey(friendNumber)
		if err != nil {
			t.Error(err, pubkey)
		}
		if pubkey != t1.t.SelfGetPublicKey() {
			t.Error("friend pubkey not match")
		}
		if !t2.t.FriendExists(friendNumber) {
			t.Error("added friend not exists")
		}
	})

	t.Run("friend status", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)

		// testing
		t1.t.CallbackFriendConnectionStatus(func(_ *Tox, friendNumber uint32, status int,
			d interface{}) {
		}, nil)
		t1nameChanged := false
		t2.t.CallbackFriendName(func(_ *Tox, friendNumber uint32, name string, d interface{}) {
			if len(name) > 0 {
				t1nameChanged = true
			}
		}, nil)
		t1statusMessageChanged := false
		t2.t.CallbackFriendStatusMessage(func(_ *Tox, friendNumber uint32, stmsg string, d interface{}) {
			if len(stmsg) > 0 {
				t1statusMessageChanged = true
			}
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)
		friendNumber, _ := t2.t.FriendAdd(t1.t.SelfGetAddress(), "hoho")

		waitcond(func() bool {
			return 1 == t1.t.SelfGetFriendListSize()
		}, 100)
		waitcond(func() bool {
			status, err := t2.t.FriendGetConnectionStatus(friendNumber)
			if err != nil {
				t.Error(err, status)
				return false
			}
			return status > CONNECTION_NONE
		}, 100)
		if status, err := t2.t.FriendGetConnectionStatus(friendNumber); err != nil || status == CONNECTION_NONE {
			t.Error(err, status)
		}

		err = t1.t.SelfSetName("t1")
		if err != nil {
			t.Error(err)
		}
		waitcond(func() bool { return t1nameChanged }, 100)
		t1name, err := t2.t.FriendGetName(friendNumber)
		t1size, err := t2.t.FriendGetNameSize(friendNumber)
		if err != nil {
			t.Error(err)
		}
		if t1name != "t1" {
			t.Error(t1name)
		}
		if t1size != len(t1name) {
			t.Error(t1size, t1name)
		}
		_, err = t1.t.SelfSetStatusMessage("t1status")
		if err != nil {
			t.Error(err)
		}
		waitcond(func() bool { return t1statusMessageChanged }, 100)
		t1stmsg, err := t2.t.FriendGetStatusMessage(friendNumber)
		if err != nil {
			t.Error(err)
		}
		if t1stmsg != "t1status" {
			t.Error(t1stmsg, t1stmsg != "t1status")
		}
		t1stmsgsz, err := t2.t.FriendGetStatusMessageSize(friendNumber)
		if err != nil {
			t.Error(err)
		}
		if t1stmsgsz != len("t1status") {
			t.Error(t1stmsgsz, len("t1status"))
		}

		t1st, err := t2.t.FriendGetStatus(friendNumber)
		if err != nil {
			t.Error(err)
		}
		if t1st != USER_STATUS_NONE {
			t.Error(t1st)
		}
	})

	t.Run("friend message", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)
		recvmsg := ""
		t1.t.CallbackFriendMessage(func(_ *Tox, friendNumber uint32, msg string, d interface{}) {
			recvmsg = msg
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)
		friendNumber, _ := t2.t.FriendAdd(t1.t.SelfGetAddress(), "hoho")
		waitcond(func() bool {
			return 1 == t1.t.SelfGetFriendListSize()
		}, 100)
		waitcond(func() bool {
			status, _ := t2.t.FriendGetConnectionStatus(friendNumber)
			return status > CONNECTION_NONE
		}, 100)
		_, err := t2.t.FriendSendMessage(friendNumber, "hohoo")
		if err != nil {
			t.Error(err)
		}
		waitcond(func() bool {
			return len(recvmsg) > 0
		}, 100)
		if recvmsg != "hohoo" {
			t.Error("send/recv message failed")
		}
		_, err = t2.t.FriendSendAction(friendNumber, "actfoo")
		if err != nil {
			t.Error(err)
		}
	})

	t.Run("friend delete", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)
		friendNumber, _ := t2.t.FriendAdd(t1.t.SelfGetAddress(), "hoho")
		waitcond(func() bool {
			return 1 == t1.t.SelfGetFriendListSize()
		}, 100)
		_, err = t2.t.FriendDelete(friendNumber)
		if err != nil {
			t.Error(err)
		}
		if t2.t.FriendExists(friendNumber) {
			t.Error("deleted friend appearence")
		}
		_, err = t2.t.FriendDelete(friendNumber)
		if err == nil {
			t.Error("delete deleted friend should failed")
		}
	})
}

// go test -v -covermode count -run Group
func TestGroup(t *testing.T) {
	t.Run("add del", func(t *testing.T) {
		t1 := NewMiniTox()
		defer t1.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)

		go t1.Iterate()
		defer t1.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2
		}, 100)
		gn, err := t1.t.AddGroupChat()
		if err != nil || gn != 0 {
			t.Error(err)
		}
		err = t1.t.DelGroupChat(gn)
		if err != nil {
			t.Error(err)
		}
		if n := t1.t.CountChatList(); n != 0 {
			t.Error(n)
		}
		if len(t1.t.GetChatList()) != 0 {
			t.Error("should 0")
		}
		var gcnt = 5
		for idx := 0; idx < gcnt; idx++ {
			gn, err = t1.t.AddGroupChat()
			if gn != idx {
				t.Error(gn, idx)
			}
			title := fmt.Sprintf("group%d", idx)
			err = t1.t.GroupSetTitle(gn, title)
			if err != nil {
				t.Error(err)
			}
			ntitle, err := t1.t.GroupGetTitle(gn)
			if err != nil {
				t.Error(err)
			}
			if ntitle != title {
				t.Errorf(`expected title "%s", got "%s"`, title, ntitle)
			}
			names := t1.t.GroupGetNames(gn)
			if len(names) != 1 {
				t.Error(len(names), 1)
			}
			pubkeys := t1.t.GroupGetPeerPubkeys(gn)
			if len(pubkeys) != 1 {
				t.Error(len(names), 1)
			}
			gtype, err := t1.t.GroupGetType(uint32(gn))
			if err != nil {
				t.Error(err)
			}
			if uint8(gtype) != GROUPCHAT_TYPE_TEXT {
				t.Error(gtype, GROUPCHAT_TYPE_TEXT)
			}
			if t1.t.GroupNumberPeers(gn) != 1 {
				t.Error(1)
			}
			pname, err := t1.t.GroupPeerName(gn, 0)
			if err != nil {
				t.Error(err)
			}
			if len(pname) != len("Tox User") {
				t.Error(pname)
			}
			pubkey, err := t1.t.GroupPeerPubkey(gn, 0)
			if err != nil {
				t.Error(err)
			}
			if !strings.HasPrefix(t1.t.SelfGetAddress(), pubkey) {
				t.Error("get peer pubkey")
			}
			if !t1.t.GroupPeerNumberIsOurs(gn, 0) {
				t.Error("ours")
			}
			if t1.t.GroupPeerNumberIsOurs(gn, 789) {
				t.Error("not ours")
			}
			err = t1.t.GroupActionSend(gn, "abc")
			if err == nil {
				t.Error("should not nil")
			}
			err = t1.t.GroupMessageSend(gn, "abc")
			if err == nil {
				t.Error("should not nil")
			}
			peers := t1.t.GroupGetPeers(gn)
			if len(peers) != 1 {
				t.Error("should 1")
			}
			if _, err = t1.t.JoinGroupChat(5, ""); err == nil {
				t.Error("should not nil")
			}
			if err = t1.t.InviteFriend(123, gn); err == nil {
				t.Error("should nil")
			}
			if cnt := t1.t.CountChatList(); int(cnt) != idx+1 {
				t.Error(cnt, idx+1)
			}
			if grps := t1.t.GetChatList(); len(grps) != idx+1 {
				t.Error(len(grps), idx+1)
			}
		}
		grps := t1.t.GetChatList()
		if len(grps) != gcnt {
			t.Error(len(grps), gcnt)
		}
		if t1.t.CountChatList() != uint32(gcnt) {
			t.Error(t1.t.CountChatList(), gcnt)
		}
	})

	t.Run("group invite", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)

		t1.t.CallbackGroupInvite(func(_ *Tox, friendNumber uint32, itype uint8, data string, ud interface{}) {
			switch itype {
			case GROUPCHAT_TYPE_TEXT:
				_, err := t1.t.JoinGroupChat(friendNumber, data)
				if err != nil {
					t.Error(err)
				}
			case GROUPCHAT_TYPE_AV:
				_, err := t1.t.JoinAVGroupChat(friendNumber, data)
				if err != nil {
					t.Error(err)
				}
			}
		}, nil)

		groupNameChangeTimes := 0
		t2.t.CallbackGroupNameListChange(func(_ *Tox, groupNumber int, peerNumber int, change uint8, ud interface{}) {
			groupNameChangeTimes++
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)

		t2.t.FriendAdd(t1.t.SelfGetAddress(), "autotests")
		waitcond(func() bool {
			return t1.t.SelfGetFriendListSize() == 1
		}, 100)

		fn, err := t2.t.FriendByPublicKey(t1.t.SelfGetPublicKey())
		if err != nil {
			t.Error(err)
		}
		gn, err := t2.t.AddGroupChat()
		if err != nil {
			t.Error(err)
		}

		// must wait friend online and can call InviteFriend
		waitcond(func() bool {
			st, err := t2.t.FriendGetConnectionStatus(fn)
			if err != nil {
				t.Error(err)
			}

			return st > CONNECTION_NONE
		}, 100)

		err = t2.t.InviteFriend(fn, gn)
		if err != nil {
			t.Error(err)
		}
		waitcond(func() bool {
			return t1.t.CountChatList() == 1
		}, 100)
		if t1.t.CountChatList() != 1 {
			t.Error("must 1 chat", t1.t.CountChatList())
		}
		if t2.t.CountChatList() != 1 {
			t.Error("must 1 chat", t2.t.CountChatList())
		}

		if err := t1.t.DelGroupChat(gn); err != nil {
			t.Error(err)
		}
		if err := t2.t.DelGroupChat(gn); err != nil {
			t.Error(err)
		}

		if groupNameChangeTimes == 0 {
			t.Error("must > 0")
		}
	})

	t.Run("group message", func(t *testing.T) {
		t1 := NewMiniTox()
		t2 := NewMiniTox()
		defer t1.t.Kill()
		defer t2.t.Kill()

		t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
			t1.t.FriendAddNorequest(friendId)
		}, nil)

		t1.t.CallbackGroupInvite(func(_ *Tox, friendNumber uint32, itype uint8, data string, ud interface{}) {
			switch itype {
			case GROUPCHAT_TYPE_TEXT:
				t1.t.JoinGroupChat(friendNumber, data)
			case GROUPCHAT_TYPE_AV:
				t1.t.JoinAVGroupChat(friendNumber, data)
			}
		}, nil)

		recved_act := ""
		recved_msg := ""
		t1.t.CallbackGroupMessage(func(_ *Tox, groupNumber, peerNumber int, msg string, ud interface{}) {
		}, nil)

		go t1.Iterate()
		go t2.Iterate()
		defer t1.stop()
		defer t2.stop()

		waitcond(func() bool {
			return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
		}, 100)

		t2.t.FriendAdd(t1.t.SelfGetAddress(), "autotests")
		waitcond(func() bool {
			return t1.t.SelfGetFriendListSize() == 1
		}, 100)

		fn, err := t2.t.FriendByPublicKey(t1.t.SelfGetPublicKey())
		if err != nil {
			t.Error(err)
		}
		gn, err := t2.t.AddGroupChat()
		if err != nil {
			t.Error(err)
		}

		// must wait friend online and can call InviteFriend
		waitcond(func() bool {
			st, _ := t2.t.FriendGetConnectionStatus(fn)
			return st > CONNECTION_NONE
		}, 100)

		err = t2.t.InviteFriend(fn, gn)
		if err != nil {
			t.Error(err)
		}
		waitcond(func() bool {
			return t1.t.CountChatList() == 1
		}, 100)

		// must wait peer join
		waitcond(func() bool {
			return t2.t.GroupNumberPeers(gn) == 2
		}, 10)

		if err := t2.t.GroupMessageSend(gn, "foo123"); err != nil {
			t.Error(err)
		}
		if err := t2.t.GroupActionSend(gn, "bar123"); err != nil {
			t.Error(err)
		}
		waitcond(func() bool {
			return len(recved_msg) > 0 && len(recved_act) > 0
		}, 10)
		if recved_msg != "foo123" || recved_act != "bar123" {
			t.Errorf(`expected "%s" and "%s", got "%s" and "%s"`, "foo123", "bar123", recved_msg, recved_act)
		}
	})
}

// go test -v -run AV
func TestAV(t *testing.T) {
	t.Run("create", func(t *testing.T) {
		if tv1, err := NewToxAV(nil); tv1 != nil {
			t.Error("must nil", err)
		}
		t1 := NewMiniTox()
		tv1, err := NewToxAV(t1.t)
		if err != nil {
			t.Error(err, tv1)
		}
	})
}

// go test -v -run File
func TestFile(t *testing.T) {
	t1 := NewMiniTox()
	t2 := NewMiniTox()

	t1.t.CallbackFriendRequest(func(_ *Tox, friendId, msg string, d interface{}) {
		t1.t.FriendAddNorequest(friendId)
	}, nil)

	t1.t.CallbackFileRecv(func(_ *Tox, friendNumber uint32, fileNumber uint32,
		kind uint32, fileSize uint64, fileName string, d interface{}) {
		t.Log(fileNumber, fileSize, fileName)
		err := t1.t.FileSeek(friendNumber, fileNumber, 15)
		if err != nil {
			t.Error(err)
		}
		err = t1.t.FileControl(friendNumber, fileNumber, FILE_CONTROL_RESUME)
		if err != nil {
			t.Error(err)
		}
	}, nil)
	recvData := ""
	t1.t.CallbackFileRecvChunk(func(this *Tox, friendNumber uint32, fileNumber uint32,
		position uint64, data []byte, d interface{}) {
		// log.Println(fileNumber, position, len(data))
		recvData += string(data)
	}, nil)
	t1.t.CallbackFileRecvControl(func(_ *Tox, friendNumber uint32, fileNumber uint32,
		control int, ud interface{}) {
		// log.Println(fileNumber, control)
	}, nil)

	t2.t.CallbackFileChunkRequest(func(_ *Tox, friend_number uint32, file_number uint32,
		position uint64, length int, d interface{}) {
		// log.Println(file_number, position, length)
		if length == 0 {
			return
		}
		s := strings.Repeat("T", length)
		_, err := t2.t.FileSendChunk(friend_number, file_number, position, []byte(s))
		if err != nil {
			t.Error(err)
		}

	}, nil)
	sendRecvDone := false
	t2.t.CallbackFileRecvControl(func(_ *Tox, friendNumber uint32, fileNumber uint32,
		control int, ud interface{}) {
		// log.Println(fileNumber, control)
		if control == FILE_CONTROL_CANCEL {
			sendRecvDone = true
		}
	}, nil)

	go t1.Iterate()
	go t2.Iterate()
	defer t1.stop()
	defer t2.stop()

	waitcond(func() bool {
		return t1.t.SelfGetConnectionStatus() == 2 && t2.t.SelfGetConnectionStatus() == 2
	}, 100)

	t2.t.FriendAdd(t1.t.SelfGetAddress(), "autotests")
	waitcond(func() bool {
		return t1.t.SelfGetFriendListSize() == 1
	}, 100)

	fn, _ := t2.t.FriendByPublicKey(t1.t.SelfGetPublicKey())
	// must wait friend online and can call InviteFriend
	waitcond(func() bool {
		st, _ := t2.t.FriendGetConnectionStatus(fn)
		return st > CONNECTION_NONE
	}, 100)

	fh, err := t2.t.FileSend(fn, FILE_KIND_DATA, 12345, "123456", "testfile.txt")
	if err != nil {
		t.Error(err, fh)
	}
	fid, err := t2.t.FileGetFileId(fn, fh)
	if len(fid) != FILE_ID_LENGTH*2 {
		t.Error("file id length not match:", len(fid), FILE_ID_LENGTH*2)
	}

	waitcond(func() bool {
		return len(recvData) > 0 && sendRecvDone
	}, 10)
	if len(recvData) != 12345-15 {
		t.Error("recv size not match")
	}

	// select {}
}

// go test -v -run Covers
func TestCovers(t *testing.T) {
	t1 := NewMiniTox()
	defer t1.t.Kill()

	tv := reflect.ValueOf(t1.t)
	mnum := tv.NumMethod()
	if false {
		t.Log(mnum)
	}

	mths := make(map[string]bool)
	for i := 0; i < mnum; i++ {
		mth := tv.Type().Method(i)
		// t.Log(i, mth.Name)
		mths[mth.Name] = true
	}

	//
	_, file, _, _ := runtime.Caller(0)
	t.Log(file)

	fset := token.NewFileSet() // positions are relative to fset

	// Parse the file containing this very example
	// but stop after processing the imports.
	f, err := parser.ParseFile(fset, file, nil, 0)
	if err != nil {
		t.Log(err)
		return
	}

	t.Log("walking ast...")
	v := &callVistor{t: t}
	v.fns = make(map[string]bool)
	ast.Walk(v, f)
	// t.Log(v.fns)

	notins := make(map[string]bool)
	for mn, _ := range mths {
		if _, ok := v.fns[mn]; !ok {
			t.Log("not tested:", mn)
			notins[mn] = false
		}
	}

	t.Log("test covers:", mnum-len(notins), mnum)
}

type callVistor struct {
	t   *testing.T
	fns map[string]bool
}

func (this *callVistor) Visit(node ast.Node) (w ast.Visitor) {
	t := this.t
	if false {
		nt := reflect.TypeOf(node)
		switch nt.Kind() {
		case reflect.Ptr:
			t.Log(nt.Elem().Kind(), nt.Elem().Name())
		default:
			t.Log(nt.Kind())
		}
	}

	switch ty := node.(type) {
	case *ast.File:
		for _, d := range ty.Decls {
			this.Visit(d)
		}
	case *ast.FuncDecl:
		this.Visit(ty.Body)
	case *ast.GenDecl:
		for _, d := range ty.Specs {
			this.Visit(d)
		}
	case *ast.BlockStmt:
		for _, s := range ty.List {
			this.Visit(s)
		}
	case *ast.ExprStmt:
		this.Visit(ty.X)
	case *ast.CallExpr:
		// t.Logf("%+v\n", ty)
		this.Visit(ty.Fun)
		for _, a := range ty.Args {
			this.Visit(a)
		}
	case *ast.FuncLit:
		this.Visit(ty.Body)
	case *ast.IfStmt:
		this.Visit(ty.Body)
		this.Visit(ty.Cond)
		if ty.Init != nil {
			this.Visit(ty.Init)
		}
		if ty.Else != nil {
			this.Visit(ty.Else)
		}
	case *ast.AssignStmt:
		for _, s := range ty.Rhs {
			this.Visit(s)
		}
	case *ast.ForStmt:
		if ty.Cond != nil {
			this.Visit(ty.Cond)
		}
		this.Visit(ty.Body)
		if ty.Init != nil {
			this.Visit(ty.Init)
		}
		if ty.Post != nil {
			this.Visit(ty.Post)
		}
	case *ast.ReturnStmt:
		for _, s := range ty.Results {
			this.Visit(s)
		}
	case *ast.SwitchStmt:
		if ty.Init != nil {
			this.Visit(ty.Init)
		}
		this.Visit(ty.Body)
	case *ast.GoStmt:
		this.Visit(ty.Call)
	case *ast.SelectStmt:
		this.Visit(ty.Body)
	case *ast.SelectorExpr:
		if ty.Sel.IsExported() {
			// t.Log(ty.Sel.String(), ty.Sel.Name, ty.X)
			this.fns[ty.Sel.Name] = true
		}
		this.Visit(ty.X)
	case *ast.BinaryExpr:
		this.Visit(ty.X)
		this.Visit(ty.Y)
	case *ast.UnaryExpr:
		this.Visit(ty.X)
	case *ast.ValueSpec:
		for _, v := range ty.Values {
			this.Visit(v)
		}
	case *ast.CaseClause:
		for _, b := range ty.Body {
			this.Visit(b)
		}
		for _, l := range ty.List {
			this.Visit(l)
		}
	default:
		if false {
			t.Logf("%+v, %+v ===\n", ty, node)
		}
	}
	// t.Log(node)
	return nil
}

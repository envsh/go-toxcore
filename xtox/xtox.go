/*
high level wrapper api for basic tox
features:
[x] auto select usable tcp port
[x] auto reconnect if disconnected
[x] auto context account info
[x] auto save/load account info
[ ] auto bootstrap
[ ] auto switch bootstrap nodes
[x] distingest self created group and invited group
[ ] event interface for callbacks replacement
[ ] with text error message
*/
// //go:generate ./getnodes.sh
package xtox

import (
	"encoding/hex"
	"io/ioutil"
	"log"
	"sync"
	"sync/atomic"
	"time"

	tox "github.com/kitech/go-toxcore"
	"github.com/kitech/godsts/maps/hashmap"
)

type ToxContext struct {
	SaveFile      string
	NickName      string
	StatusMessage string
}

func NewToxContext(SaveFile, NickName, StatusMessage string) *ToxContext {
	return &ToxContext{SaveFile, NickName, StatusMessage}
}

func New(ctx *ToxContext) *tox.Tox {
	t, opts := tryNew(ctx)
	if t != nil {
		ctxmu.Lock()
		defer ctxmu.Unlock()
		xt := newXTox()
		xt.opts = opts
		xt.t = t
		if ctx != nil {
			xt.ctx = ctx
		}
		t.SelfSetName(xt.ctx.NickName)
		t.SelfSetStatusMessage(xt.ctx.StatusMessage)
		t.WriteSavedata(xt.ctx.SaveFile)
		log.Println("ID:", t.SelfGetAddress())
		xt.initCallbacks()
		xt.initHooks()
		ctxs[t] = xt
	}
	return t
}

func IsInvitedGroup(t *tox.Tox, groupNumber uint32) bool {
	xt := ctxs[t]
	_, found := xt.invitedGroups.Get(groupNumber)
	return found
}

/////
var ctxmu sync.Mutex
var ctxs = map[*tox.Tox]*_XTox{}

type _XTox struct {
	opts           *tox.ToxOptions
	ctx            *ToxContext
	t              *tox.Tox
	oilC           chan interface{}
	invitedGroups  *hashmap.Map
	groupPeerKeys  *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => pubkey
	groupPeerNames *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => name
	needReconn     int32
}

func tryNew(ctx *ToxContext) (*tox.Tox, *tox.ToxOptions) {
	opts := tox.ToxOptions{}
	opts.ThreadSafe = true
	opts.Udp_enabled = true

	if tox.FileExist(ctx.SaveFile) {
		bcc, err := ioutil.ReadFile(ctx.SaveFile)
		if err != nil {
			log.Println(err)
		} else {
			opts.Savedata_data = bcc
			opts.Savedata_type = tox.SAVEDATA_TYPE_TOX_SAVE
		}
	}

	for port := 33445 + 5; port < 65536; port++ {
		opts.Tcp_port = uint16(port)
		t := tox.NewTox(&opts)
		if t != nil {
			log.Println(opts.Tcp_port)
			return t, &opts
		}
	}
	return nil, nil
}

func newXTox() *_XTox {
	xt := &_XTox{}
	xt.oilC = make(chan interface{}, 0)
	xt.invitedGroups = hashmap.New()
	xt.groupPeerKeys = hashmap.New()
	xt.groupPeerNames = hashmap.New()
	xt.ctx = NewToxContext("toxsave.bin", "xtoxuser", "xtoxuser!!!")
	return xt
}

func (this *_XTox) tryReconn() {
	t := this.t
	status := t.SelfGetConnectionStatus()

	if status == tox.CONNECTION_NONE {
		atomic.CompareAndSwapInt32(&this.needReconn, 0, 1)
		time.AfterFunc(3*time.Second, func() {
			if atomic.LoadInt32(&this.needReconn) == 1 {
				log.Println("Reconneting...")
				Connect(t)
				time.AfterFunc(4*time.Second, this.tryReconn)
			}
		})
	} else {
		atomic.CompareAndSwapInt32(&this.needReconn, 1, 0)
	}
}

func (this *_XTox) initCallbacks() {
	t := this.t
	t.CallbackConferenceInviteAdd(func(_ *tox.Tox, friendNumber uint32, itype uint8, data []byte, userData interface{}) {
		// hdata := hex.EncodeToString(data)
		// this.invitedGroups.Add(hdata)
	}, nil)

	t.CallbackSelfConnectionStatusAdd(func(_ *tox.Tox, status int, userData interface{}) {
		if status == tox.CONNECTION_NONE {
		} else {
			t.WriteSavedata(this.ctx.SaveFile)
		}
		this.tryReconn()
	}, nil)
	t.CallbackFriendConnectionStatusAdd(func(_ *tox.Tox, friendNumber uint32, status int, userData interface{}) {
		// friendName, _ := t.FriendGetName(friendNumber)
		// log.Println(friendNumber, friendName, status, tox.ConnStatusString(status))
		t.WriteSavedata(this.ctx.SaveFile)
	}, nil)
	t.CallbackConferenceNameListChangeAdd(func(_ *tox.Tox, groupNumber uint32, peerNumber uint32, change uint8, userData interface{}) {
		switch change {
		case tox.CHAT_CHANGE_PEER_ADD:
			fallthrough
		case tox.CHAT_CHANGE_PEER_NAME:
			pubkey, err := t.ConferencePeerGetPublicKey(groupNumber, peerNumber)
			if err == nil {
				// assert found == true
				peerKeysx, _ := this.groupPeerKeys.Get(groupNumber)
				peerKeysx.(*hashmap.Map).Put(peerNumber, pubkey)
			}
			peerName, err := t.ConferencePeerGetName(groupNumber, peerNumber)
			if err == nil {
				peerNamesx, _ := this.groupPeerNames.Get(groupNumber)
				peerNamesx.(*hashmap.Map).Put(peerNumber, peerName)
			}
		}
	}, nil)
}

func (this *_XTox) initHooks() {
	t := this.t
	t.HookConferenceJoin(func(friendNumber uint32, groupNumber uint32, data []byte) {
		if !this.groupPeerKeys.Has(groupNumber) {
			this.groupPeerKeys.Put(groupNumber, hashmap.New())
		} else {
			this.groupPeerKeys.Put(groupNumber, hashmap.New()) // 这时再清空比较好
		}
		if !this.groupPeerNames.Has(groupNumber) {
			this.groupPeerNames.Put(groupNumber, hashmap.New())
		} else {
			this.groupPeerNames.Put(groupNumber, hashmap.New()) // 这时再清空比较好
		}
		hdata := hex.EncodeToString(data)
		this.invitedGroups.Put(groupNumber, hdata)
		// log.Println(friendNumber, groupNumber)
	})
	t.HookConferenceDelete(func(groupNumber uint32) {
		this.invitedGroups.Remove(groupNumber)
	})
}

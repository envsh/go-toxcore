/*
high level wrapper api for basic tox
features:
[x] auto select usable tcp port
[x] auto reconnect if disconnected
[x] auto context account info
[x] auto save/load account info
[x] auto bootstrap
[ ] auto switch bootstrap nodes
[x] distinguish self created group and invited group
[ ] record group inviter
[ ] record invited group cookie
[ ] event interface for callbacks replacement
[ ] with text error message
[x] duplicate store title info of groups
[x] duplicate store peer info of groups
*/
// //go:generate ./getnodes.sh
package xtox

/*
#include <tox/tox.h>
#include <tox/toxav.h>
*/
import "C"

import (
	"io/ioutil"
	"log"
	"sync"
	"sync/atomic"
	"time"

	// tox "github.com/kitech/go-toxcore"
	tox "github.com/TokTok/go-toxcore-c"
	"github.com/kitech/godsts/maps/hashbidimap"
	"github.com/kitech/godsts/maps/hashmap"
	funk "github.com/thoas/go-funk"
)

const (
	CHAT_CHANGE_PEER_ADD  = uint8(0)
	CHAT_CHANGE_PEER_DEL  = uint8(1)
	CHAT_CHANGE_PEER_NAME = uint8(2)
)

type ToxContext struct {
	SaveFile      string
	NickName      string
	StatusMessage string
	ForceSet      bool
}

func NewToxContext(SaveFile, NickName, StatusMessage string) *ToxContext {
	return &ToxContext{SaveFile, NickName, StatusMessage, false}
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
		xt.Tox = t
		xt.toxcore = (*C.Tox)(GetCTox(t))

		// when current name is empty for force set
		if t.SelfGetName() == "" || ctx.ForceSet == true {
			t.SelfSetName(xt.ctx.NickName)
			t.SelfSetStatusMessage(xt.ctx.StatusMessage)
		}
		err := t.WriteSavedata(xt.ctx.SaveFile)
		if err != nil {
			log.Println(err)
		}
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
	*tox.Tox
	*tox.ToxAV

	toxcore *C.Tox
	toxav   *C.ToxAV

	opts             *tox.ToxOptions
	ctx              *ToxContext
	t                *tox.Tox
	oilC             chan interface{}
	invitedGroups    *hashbidimap.Map
	groupIdentifiers *hashbidimap.Map
	groupPeerKeys    *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => pubkey
	groupPeerNames   *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => name
	groupTitles      *hashmap.Map // uint32 => string, group number => group title
	groupPeers       *hashmap.Map // TODO uint32 => Map[uint32]*PeerInfo
	needReconn       int32
}

func tryNew(ctx *ToxContext) (*tox.Tox, *tox.ToxOptions) {
	opts := tox.ToxOptions{}
	opts.ThreadSafe = true
	opts.Udp_enabled = true
	opts.Udp_enabled = false

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
	xt.invitedGroups = hashbidimap.New()
	xt.groupIdentifiers = hashbidimap.New()
	xt.groupPeerKeys = hashmap.New()
	xt.groupPeerNames = hashmap.New()
	xt.groupTitles = hashmap.New()
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
	t.CallbackConferenceInviteAdd(func(_ *tox.Tox, friendNumber uint32, itype uint8, cookie string, userData interface{}) {
		// hdata := hex.EncodeToString(data)
		// this.invitedGroups.Add(hdata)
	}, nil)

	t.CallbackSelfConnectionStatusAdd(func(_ *tox.Tox, status int, userData interface{}) {
		if status == tox.CONNECTION_NONE {
		} else {
			err := t.WriteSavedata(this.ctx.SaveFile)
			if err != nil {
				log.Println(err)
			}
		}
		this.tryReconn()
	}, nil)
	t.CallbackFriendConnectionStatusAdd(func(_ *tox.Tox, friendNumber uint32, status int, userData interface{}) {
		// friendName, _ := t.FriendGetName(friendNumber)
		// log.Println(friendNumber, friendName, status, tox.ConnStatusString(status))
		err := t.WriteSavedata(this.ctx.SaveFile)
		if err != nil {
			log.Println(err)
		}
	}, nil)
	t.CallbackConferencePeerNameAdd(func(_ *tox.Tox, groupNumber uint32, peerNumber uint32, peerName string, userData interface{}) {
		peerNamesx, found := this.groupPeerNames.Get(groupNumber)
		if !found {
			peerNamesx = hashmap.New()
			this.groupPeerNames.Put(groupNumber, peerNamesx)
		}

		peerNamesx.(*hashmap.Map).Put(peerNumber, peerName)
	}, nil)
	t.CallbackConferencePeerListChangedAdd(func(_ *tox.Tox, groupNumber uint32, userData interface{}) {
		pubkeys := t.ConferenceGetPeerPubkeys(groupNumber)
		peerKeysx, found := this.groupPeerKeys.Get(groupNumber)
		if !found {
			peerKeysx = hashmap.New()
			this.groupPeerKeys.Put(groupNumber, peerKeysx)
		}
		var addedKeys []string
		var deletedKeys []string
		peerKeys := peerKeysx.(*hashmap.Map)
		for _, pubkey := range pubkeys {
			if !funk.Contains(peerKeys.Values(), pubkey) {
				addedKeys = append(addedKeys, pubkey)
			}
		}
		for _, pubkeyx := range peerKeys.Values() {
			if !funk.Contains(pubkeys, pubkeyx) {
				deletedKeys = append(deletedKeys, pubkeyx.(string))
			}
		}
		// log.Println("added:", len(addedKeys), "deleted:", len(deletedKeys), "gn:", groupNumber)
		peerKeys.Clear()
		for num, pubkey := range pubkeys {
			peerKeys.Put(uint32(num), pubkey)
		}
	}, nil)
	/*
		t.CallbackConferenceNameListChangeAdd(func(_ *tox.Tox, groupNumber uint32, peerNumber uint32, change uint8, userData interface{}) {
			switch change {
			case tox.CHAT_CHANGE_PEER_ADD:
				fallthrough
			case tox.CHAT_CHANGE_PEER_NAME:
				pubkey, err := t.ConferencePeerGetPublicKey(groupNumber, peerNumber)
				if err == nil {
					// assert found == true
					peerKeysx, found := this.groupPeerKeys.Get(groupNumber)
					if !found {
						peerKeysx = hashmap.New()
						this.groupPeerKeys.Put(groupNumber, peerKeysx)
					}

					peerKeysx.(*hashmap.Map).Put(peerNumber, pubkey)
				} else {
					log.Println(err, groupNumber, peerNumber)
				}
				peerName, err := t.ConferencePeerGetName(groupNumber, peerNumber)
				if err == nil {
					peerNamesx, found := this.groupPeerNames.Get(groupNumber)
					if !found {
						peerNamesx = hashmap.New()
						this.groupPeerNames.Put(groupNumber, peerNamesx)
					}

					peerNamesx.(*hashmap.Map).Put(groupNumber, peerName)
				} else {
					log.Println(err, groupNumber, peerNumber)
				}
			}
		}, nil)
	*/
	t.CallbackConferenceTitleAdd(func(_ *tox.Tox, groupNumber uint32, peerNumber uint32, title string, userData interface{}) {
		this.groupTitles.Put(groupNumber, title)
		// log.Println("set group title:", groupNumber, title)
	}, nil)
}

func (this *_XTox) initHooks() {
	t := this.t
	t.HookConferenceJoin(func(friendNumber uint32, groupNumber uint32, cookie string) {
		// 刚join的时候无法获取title
		if !this.groupPeerKeys.Has(groupNumber) {
			this.groupPeerKeys.Put(groupNumber, hashmap.New())
		} else {
			// this.groupPeerKeys.Put(groupNumber, hashmap.New()) // 这时再清空比较好
			// 这里不能清空。由于时序问题，可能先收到NameListChanged回调
		}
		if !this.groupPeerNames.Has(groupNumber) {
			this.groupPeerNames.Put(groupNumber, hashmap.New())
		} else {
			// this.groupPeerNames.Put(groupNumber, hashmap.New()) // 这时再清空比较好
		}
		this.invitedGroups.Put(groupNumber, cookie)
		// log.Println(friendNumber, groupNumber)

		groupId := ConferenceCookieToIdentifier(cookie)
		if !ConferenceIdIsEmpty(groupId) {
			this.groupIdentifiers.Put(groupNumber, groupId)
			this.groupIdentifiers.Put(groupId, groupNumber)
		}
	})
	t.HookConferenceDelete(func(groupNumber uint32) {
		time.AfterFunc(3*time.Minute, func() {
			if value, found := this.invitedGroups.Get(groupNumber); found {
				this.invitedGroups.Remove(groupNumber)
				this.invitedGroups.RemoveValue(value)
			}
			if value, found := this.groupIdentifiers.Get(groupNumber); found {
				this.groupIdentifiers.Remove(groupNumber)
				this.groupIdentifiers.RemoveValue(value)
			}
		})
	})
	t.HookConferenceNew(func(groupNumber uint32) {
		if !this.groupPeerKeys.Has(groupNumber) {
			this.groupPeerKeys.Put(groupNumber, hashmap.New())
		} else {
			this.groupPeerKeys.Put(groupNumber, hashmap.New()) // 这时再清空比较好
		}
		if valuex, found := this.groupPeerKeys.Get(groupNumber); found {
			valuex.(*hashmap.Map).Put(0, t.SelfGetPublicKey())
		}

		if !this.groupPeerNames.Has(groupNumber) {
			this.groupPeerNames.Put(groupNumber, hashmap.New())
		} else {
			this.groupPeerNames.Put(groupNumber, hashmap.New()) // 这时再清空比较好
		}
		if valuex, found := this.groupPeerNames.Get(groupNumber); found {
			valuex.(*hashmap.Map).Put(0, t.SelfGetName())
		}

		grpid, err := t.ConferenceGetIdentifier(groupNumber)
		if err == nil {
			this.groupIdentifiers.Put(groupNumber, grpid)
			this.groupIdentifiers.Put(grpid, groupNumber)
		}
	})
	t.HookConferenceSetTitle(func(groupNumber uint32, title string) {
		this.groupTitles.Put(groupNumber, title)
		// log.Println("set group title:", groupNumber, title)
	})
}

type PeerInfo struct {
	Number uint32
	Pubkey string
	Name   string
}

type FriendInfo struct {
	PeerInfo
	StatusMessage string
	Status        uint32
	LastSeen      uint32
}

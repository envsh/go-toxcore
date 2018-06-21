package xtox

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"gopp"
	"log"
	"math"
	"runtime/debug"
	"strings"
	"time"

	// tox "github.com/kitech/go-toxcore"
	tox "github.com/TokTok/go-toxcore-c"
	"github.com/kitech/godsts/maps/hashmap"
)

func ConferenceAllTitles(this *tox.Tox) map[uint32]string {
	ret := map[uint32]string{}
	cids := this.ConferenceGetChatlist()
	for _, cid := range cids {
		title, err := this.ConferenceGetTitle(cid)
		if err != nil {
			continue
		}
		ret[cid] = title
	}
	return ret
}

func ConferenceFind /*ByTitle*/ (this *tox.Tox, title string) (gn uint32, found bool) {
	cids := this.ConferenceGetChatlist()
	for _, cid := range cids {
		title_, err := this.ConferenceGetTitle(cid)
		if err != nil {
			continue
		}
		if title_ == title {
			return cid, true
		}
	}
	return math.MaxUint32, false
}

func ConferenceFindAll(this *tox.Tox, title string) (gns []uint32, found bool) {
	gns = make([]uint32, 0)
	cids := this.ConferenceGetChatlist()
	for _, cid := range cids {
		title_, err := this.ConferenceGetTitle(cid)
		if err != nil {
			continue
		}
		if title_ == title {
			found = true
			gns = append(gns, cid)
		}
	}
	return gns, found
}

func ConferenceFindPeer(this *tox.Tox, name string) (pubkey string, found bool) {
	cids := this.ConferenceGetChatlist()
	for _, cid := range cids {
		names := this.ConferenceGetNames(cid)
		foundName := false
		foundIndex := 0
		for idx, tname := range names {
			if tname == name {
				foundName = true
				foundIndex = idx
				break
			}
		}
		if !foundName {
			continue
		}
		peers := this.ConferenceGetPeers(cid)
		pubkey, found = peers[uint32(foundIndex)]

		if foundName {
			break
		}
	}
	return
}

func IsSelfGroupMessage(t *tox.Tox, groupNumber int, peerNumber int) bool {
	selfMessage := false
	peerPubkey, err := t.GroupPeerPubkey(groupNumber, peerNumber)
	if err != nil {
		return false
	}
	if strings.HasPrefix(t.SelfGetAddress(), peerPubkey) {
		selfMessage = true
	}
	return selfMessage
}

func GetAllFriendList(t *tox.Tox) (friends []uint32) {
	for fn := uint32(0); fn < math.MaxUint32; fn++ {
		if t.FriendExists(fn) {
			friends = append(friends, fn)
		} else {
			break
		}
	}
	return
}

func CountFriend(t *tox.Tox) (n int) {
	for fn := uint32(0); fn < math.MaxUint32; fn++ {
		if t.FriendExists(fn) {
			n += 1
		} else {
			return
		}
	}
	return
}

func FindFriendByName(t *tox.Tox, name string) (pubkey string, found bool) {
	for i := uint32(0); i < 256; i++ {
		if t.FriendExists(i) {
			tname, err := t.FriendGetName(i)
			gopp.ErrPrint(err, tname)
			if err == nil && tname == name {
				found = true
				pubkey, _ = t.FriendGetPublicKey(i)
				break
			}
		} else {
			break
		}
	}
	return
}

func ConferencePeerGetPubkey(t *tox.Tox, groupNumber uint32, peerNumber uint32) (pubkey string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if peerKeysx, foundg := xt.groupPeerKeys.Get(groupNumber); foundg {
		if pubkeyx, foundp := peerKeysx.(*hashmap.Map).Get(peerNumber); foundp {
			pubkey, found = pubkeyx.(string), foundp
		}
	}
	return
}

func ConferencePeerGetName(t *tox.Tox, groupNumber uint32, peerNumber uint32) (name string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if peerNames, foundg := xt.groupPeerNames.Get(groupNumber); foundg {
		if namex, foundp := peerNames.(*hashmap.Map).Get(peerNumber); foundp {
			name, found = namex.(string), foundp
		}
	}
	return
}

func ConferenceGetTitle(t *tox.Tox, groupNumber uint32) (title string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	// log.Println(groupNumber, xt.groupTitles.String())
	if namex, found := xt.groupTitles.Get(groupNumber); found {
		return namex.(string), found
	}
	return
}

func ConferenceGetCookie(t *tox.Tox, groupNumber uint32) (cookie string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if cookiex, found := xt.invitedGroups.Get(groupNumber); found {
		return cookiex.(string), found
	}
	return
}

func ConferenceGetByCookie(t *tox.Tox, cookie string) (groupNumber uint32, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if groupNumberx, found := xt.invitedGroups.GetKey(cookie); found {
		return groupNumberx.(uint32), found
	}
	return
}

func ConferenceGetIdentifier_s(t *tox.Tox, groupNumber uint32) (groupId string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if groupIdx, found := xt.groupIdentifiers.Get(groupNumber); found {
		return groupIdx.(string), found
	}
	// backward get
	groupId, err := t.ConferenceGetIdentifier(groupNumber)
	if err == nil {
		if !ConferenceIdIsEmpty(groupId) {
			xt.groupIdentifiers.Put(groupNumber, groupId)
			return groupId, true
		}
	}
	return
}

func ConferenceGetByIdentifier(t *tox.Tox, identifier string) (groupNumber uint32, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if groupNumberx, found := xt.groupIdentifiers.GetKey(identifier); found {
		return groupNumberx.(uint32), found
	}
	return
}

// remote group number(2B)+type(1B)+identifier(32B)
func ConferenceCookieToIdentifier(cookie string) string {
	if len(cookie) >= 6 {
		return cookie[6:]
	}
	return ""
}

func ConferenceIdIsEmpty(groupId string) bool {
	return groupId == "" || strings.Replace(groupId, "0", "", -1) == ""
}

func ConferenceNameToIdentifier(name string) string {
	hname := sha256.Sum256([]byte(name))
	return strings.ToUpper(hex.EncodeToString(hname[:]))
}

func deperated_ConferenceNameToIdentifier(name string) string {
	hname := md5.Sum([]byte(name))
	rname := gopp.StrReverse(name)
	hrname := md5.Sum([]byte(rname))
	return hex.EncodeToString(hname[:]) + hex.EncodeToString(hrname[:])
}

func Connect(this *tox.Tox) error {
	err := _Connect(this)

	go func() {
		for i := 0; i < 10; i++ {
			time.Sleep(10 * time.Second)
			if this.SelfGetConnectionStatus() > 0 {
				break
			}
			_Connect(this)
		}
	}()

	return err
}

func _Connect(this *tox.Tox) error {
	defer func() {
		if err := recover(); err != nil {
			log.Println(err)
			debug.PrintStack()
		}
	}()

	// bootstrap
	fixedNodes := []ToxNode{
		ToxNode{Ipaddr: "194.249.212.109", Port: uint16(33445), Pubkey: "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B"},
		ToxNode{Ipaddr: "130.133.110.14", Port: uint16(33445), Pubkey: "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F"},
		ToxNode{Ipaddr: "85.172.30.117", Port: uint16(33445), Pubkey: "8E7D0B859922EF569298B4D261A8CCB5FEA14FB91ED412A7603A585A25698832"},
	}
	var err error
	for _, n := range fixedNodes {
		_, err = this.Bootstrap(n.Ipaddr, n.Port, n.Pubkey)
		_, err = this.AddTcpRelay(n.Ipaddr, n.Port, n.Pubkey)
	}

	nodes := get3nodes()
	for _, n := range nodes {
		if n.Ipaddr == "" || n.Pubkey == "" {
			continue
		}
		_, err = this.Bootstrap(n.Ipaddr, n.Port, n.Pubkey)
		if n.status_tcp {
			_, err = this.AddTcpRelay(n.Ipaddr, n.Port, n.Pubkey)
		}
	}

	return err
}

// connect one fixed node
func ConnectFixed(this *tox.Tox) error {
	defer func() {
		if err := recover(); err != nil {
		}
	}()

	// bootstrap
	fixedNodes := []ToxNode{
		ToxNode{Ipaddr: "cotox.tk", Port: uint16(33445), Pubkey: "AF66C5FFAA6CA67FB8E287A5B1D8581C15B446E12BF330963EF29E3AFB692918"},
	}
	var err error
	for _, n := range fixedNodes {
		_, err = this.Bootstrap(n.Ipaddr, n.Port, n.Pubkey)
		_, err = this.AddTcpRelay(n.Ipaddr, n.Port, n.Pubkey)
		break
	}

	return err
}

func CheckId(s string) bool {
	if len(s) != tox.PUBLIC_KEY_SIZE*2+12 {
		return false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return false
	}
	// TODO checksum
	return true
}

func CheckPubkey(s string) bool {
	if len(s) != tox.PUBLIC_KEY_SIZE*2 {
		return false
	}
	if _, err := hex.DecodeString(s); err != nil {
		return false
	}
	return true
}

// support long text
// possible error, send half, error send half
// split by char, or split by line
// if split by line, if the line is too long, still use split by char for the line
func FriendSendMessage(t *tox.Tox, friendNumber uint32, mtype int, msg string) {

}

// should block
// TODO when OS hibenate long time, and then wakeup,
// tick will loop run hibenate-time/tick count. like a nonblock deadloop.
// this isn't what we want
func Run(t *tox.Tox, tav *tox.ToxAV) {
	_RunWithSleep(t, tav)
}
func _RunWithTicker(t *tox.Tox, tav *tox.ToxAV) {
	tmer := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-tmer.C:
			t.Iterate2(nil)
			if tav != nil {
				tav.Iterate()
			}
		}
	}
}
func _RunWithSleep(t *tox.Tox, tav *tox.ToxAV) {
	if tav != nil {
		go func() {
			for {
				time.Sleep(time.Duration(tav.IterationInterval()) * time.Millisecond)
				tav.Iterate()
			}
		}()
	}
	for {
		time.Sleep(200 * time.Millisecond)
		t.Iterate2(nil)
	}
}

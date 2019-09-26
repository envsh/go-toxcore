package xtox

import (
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"gopp"
	"math"
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

// support both text and audio
func ConferenceJoin(t *tox.Tox, friendNumber uint32, itype uint8, cookie string,
	cbfn func(_ *tox.Tox, groupNumber uint32, peerNumber uint32, pcm []byte,
		samples uint, channels uint8, sample_rate uint32, userData interface{})) (uint32, error) {
	// 0000 4byte is peer group number
	if cookie[5] == 49 /* char '1' */ && itype == tox.CONFERENCE_TYPE_AV {
		return t.JoinAVGroupChat(friendNumber, cookie, cbfn)
	} else {
		return t.ConferenceJoin(friendNumber, cookie)
	}
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
	nums := t.ConferenceGetChatlist()
	for _, num := range nums {
		groupId, err := t.ConferenceGetIdentifier(num)
		gopp.ErrFatal(err)
		if groupId == identifier {
			groupNumber, found = num, true
			break
		}
	}
	return
}
func ConferenceGetByIdentifier_dep(t *tox.Tox, identifier string) (groupNumber uint32, found bool) {
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

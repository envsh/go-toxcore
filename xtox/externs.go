package xtox

import (
	"encoding/hex"
	"gopp"
	"math"
	"strings"
	"time"

	tox "github.com/kitech/go-toxcore"
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

func ConferenceGetIdentifier(t *tox.Tox, groupNumber uint32) (groupId string, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if groupIdx, found := xt.groupIdentifiers.Get(groupNumber); found {
		return groupIdx.(string), found
	}
	return
}

func ConferenceGetByIdentifier(t *tox.Tox, cookie string) (groupNumber uint32, found bool) {
	ctxmu.Lock()
	defer ctxmu.Unlock()

	xt := ctxs[t]
	if groupNumberx, found := xt.groupIdentifiers.GetKey(cookie); found {
		return groupNumberx.(uint32), found
	}
	return
}

func ConferenceCookieToIdentifier(cookie string) string {
	if len(cookie) >= 6 {
		return cookie[6:]
	}
	return ""
}

func ConferenceIdIsEmpty(groupId string) bool {
	return groupId == "" || strings.Replace(groupId, "0", "", -1) == ""
}

func Connect(this *tox.Tox) error {
	// bootstrap
	_, err := this.Bootstrap("194.249.212.109", 33445, "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B")
	_, err = this.Bootstrap("130.133.110.14", 33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F")
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
func Run(t *tox.Tox) {
	tmer := time.NewTicker(200 * time.Millisecond)
	for {
		select {
		case <-tmer.C:
			t.Iterate2(nil)
		}
	}
}

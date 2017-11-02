package xtox

import (
	"encoding/hex"
	"math"
	"strings"

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

func ConferenceFind(this *tox.Tox, title string) (gn uint32, found bool) {
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

func Connect(this *tox.Tox) error {
	// bootstrap
	this.Bootstrap("194.249.212.109", 33445, "3CEE1F054081E7A011234883BC4FC39F661A55B73637A5AC293DDF1251D9432B")
	this.Bootstrap("130.133.110.14", 33445, "461FA3776EF0FA655F1A05477DF1B3B614F7D6B124F7DB1DD4FE3C08B03B640F")
	return nil
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

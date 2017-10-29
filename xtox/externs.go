package xtox

import (
	"encoding/hex"
	"math"

	tox "github.com/kitech/go-toxcore"
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

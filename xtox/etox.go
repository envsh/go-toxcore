package xtox

import (
	// tox "github.com/kitech/go-toxcore"
	tox "github.com/TokTok/go-toxcore-c"
	"github.com/kitech/godsts/maps/hashmap"
)

type EasyTox struct {
	*tox.Tox

	opts           *tox.ToxOptions
	ctx            *ToxContext
	t              *tox.Tox
	oilC           chan interface{}
	invitedGroups  *hashmap.Map
	groupPeerKeys  *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => pubkey
	groupPeerNames *hashmap.Map // uint32 => Map[uint32]pubkey, group number => peer number => name
	needReconn     int32
}

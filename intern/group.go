package toxin

/*
#include "group.h"
*/
import "C"
import (
	"unsafe"
)

type GroupPeer struct {
	cthis *C.Group_Peer
}

func NewGroupPeerFromPointer(cthis unsafe.Pointer) *GroupPeer {
	this := &GroupPeer{}
	this.cthis = (*C.Group_Peer)(cthis)
	return this
}

func (this *GroupPeer) RealPK() string {
	return ppkey2str(&this.cthis.real_pk[0])
}

func (this *GroupPeer) TempPK() string {
	return ppkey2str(&this.cthis.temp_pk[0])
}

func (this *GroupPeer) Name() string {
	return C.GoStringN((*C.char)(unsafe.Pointer(&this.cthis.nick[0])), C.int(this.cthis.nick_len))
}

type GroupChat struct {
	cthis *C.Group_c
}

func NewGroupChatFromPointer(cthis unsafe.Pointer) *GroupChat {
	this := &GroupChat{}
	this.cthis = (*C.Group_c)(cthis)
	return this
}

type GroupChats struct {
	cthis *C.Group_Chats
}

func NewGroupChatsFromPointer(cthis unsafe.Pointer) *GroupChats {
	this := &GroupChats{}
	this.cthis = (*C.Group_Chats)(cthis)
	return this
}

func (this *GroupChats) GetChat(index int) *GroupChat {
	p := addrStep(unsafe.Pointer(this.cthis), index*C.sizeof_Group_c)
	return NewGroupChatFromPointer(p)
}

func (this *GroupChats) NumChats() int {
	return int(this.cthis.num_chats)
}

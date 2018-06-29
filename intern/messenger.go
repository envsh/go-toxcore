package toxin

/*
#include "Messenger.h"
*/
import "C"
import "unsafe"

type Friend struct {
	cthis *C.Friend
}

func NewFriendFromPointer(cthis unsafe.Pointer) *Friend {
	this := &Friend{}
	this.cthis = (*C.Friend)(cthis)
	return this
}

type Messenger struct {
	cthis *C.Messenger
}

func NewMessagerFromPointer(cthis unsafe.Pointer) *Messenger {
	this := &Messenger{}
	this.cthis = (*C.Messenger)(cthis)
	return this
}

func (this *Messenger) GetChats() *GroupChats {
	return NewGroupChatsFromPointer(unsafe.Pointer(this.cthis.conferences_object))
}

func (this *Messenger) GetFriend(index int) *Friend {
	p := addrStep(unsafe.Pointer(this.cthis.friendlist), index*C.sizeof_Friend)
	return NewFriendFromPointer(p)
}

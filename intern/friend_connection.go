package toxin

/*
#include "friend_connection.h"
*/
import "C"
import "unsafe"

type FriendConn struct {
	cthis *C.Friend_Conn
}

func NewFriendConnFromPointer(cthis unsafe.Pointer) *FriendConn {
	this := &FriendConn{}
	this.cthis = (*C.Friend_Conn)(cthis)
	return this
}

func (this *FriendConn) RealPK() string {
	return ppkey2str(&this.cthis.real_public_key[0])
}

func (this *FriendConn) TempPk() string {
	return ppkey2str(&this.cthis.dht_temp_pk[0])
}

func (this *FriendConn) Host() *IP_Port {
	return nil
}

type FriendConnections struct {
	cthis *C.Friend_Connections
}

func NewFriendConnectionsFromPointer(cthis unsafe.Pointer) *FriendConnections {
	this := &FriendConnections{}
	this.cthis = (*C.Friend_Connections)(cthis)
	return this
}

func (this *FriendConnections) GetConn(index int) *FriendConn {
	p := addrStep(unsafe.Pointer(this.cthis.conns), index*C.sizeof_Friend_Conn)
	return NewFriendConnFromPointer(p)
}

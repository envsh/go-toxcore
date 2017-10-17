package toxin

/*
#include "DHT.h"
*/
import "C"
import "unsafe"

//
func (this *DHT) GetFriendList() *DHTFriendList {
	return NewDHTFriendListFrom(this.dht.friends_list, this.dht.num_friends)
}

func (this *DHT) GetToBootstrap() *NodeFormatList {
	return NewNodeFormatList((*C.Node_format)((unsafe.Pointer)(&this.dht.to_bootstrap[0])),
		int(this.dht.num_to_bootstrap))
}

func (this *DHT) GetClientDataList() *ClientDataList {
	return NewClientDataListFrom((*C.Client_data)((unsafe.Pointer)(&this.dht.close_clientlist[0])), C.LCLIENT_LIST)
}

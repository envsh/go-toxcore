package mintox

import (
	"encoding/binary"
	"gopp"
	"log"
	"net"
	"strings"
)

func (this *DHT) sendnodes_ipv6(addr net.Addr, pubkey *CryptoKey, clientid *CryptoKey, sbdata []byte, shrkey *CryptoKey) int {
	tip := net.IPv4(0, 0, 0, 0)
	taddr := &net.UDPAddr{}
	taddr.IP = tip
	taddr.Port = 12345

	nodes := this.get_close_nodes(pubkey, 0, false, true)
	// log.Println("will send nodes:", len(nodes))
	if len(nodes) <= 0 {
		return 0
	}

	buf := gopp.NewBufferZero()
	buf.WriteByte(byte(len(nodes)))
	for _, node := range nodes {
		// log.Println("packed node:", node.Addr, node.Pubkey.ToHex20())
		buf.Write(pack_ip_port(node.Addr))
		buf.Write(node.Pubkey.Bytes())
	}
	buf.Write(sbdata)
	pkt, err := this.CreatePacket(this.SelfPubkey, shrkey, NET_PACKET_SEND_NODES_IPV6, buf.Bytes())
	gopp.ErrPrint(err)
	wn, err := this.Neto.WriteTo(pkt, addr)
	gopp.ErrPrint(err, wn, addr)
	log.Println("sent nodes to:", len(nodes), wn, addr)
	return 0
}

func (this *DHT) add_to_ping(pubkey *CryptoKey, addr net.Addr) {

}

func pack_ip_port(addr net.Addr) []byte {
	buf := gopp.NewBufferZero()

	is_ipv4, net_family := true, byte(TOX_AF_INET)
	_ = is_ipv4
	if strings.HasPrefix(addr.String(), "[") {
		is_ipv4 = false
		net_family = TOX_AF_INET6
	}

	buf.WriteByte(net_family)
	uaddr := addr.(*net.UDPAddr)
	if is_ipv4 {
		buf.Write(uaddr.IP.To4())
	} else {
		buf.Write(uaddr.IP)
	}
	buf.Write([]byte{0, 0})
	binary.Write(buf.WBufAt(1+4), binary.BigEndian, uint16(uaddr.Port))
	// unpack_ip_port(buf.Bytes()) // for self unpack test
	return buf.Bytes()
}

func unpack_ip_port(data []byte) {
	tmpbuf := gopp.NewBufferBuf(data)
	var i = 0

	byte0, _ := tmpbuf.ReadByte()
	istcp := byte0&128 == 1
	isip6 := byte0&127 == 10
	log.Printf("node: %d, %s, %s\n", i, gopp.IfElseStr(istcp, "TCP", "UDP"),
		gopp.IfElseStr(isip6, "IPV6", "IPV4"))
	var ipobj net.IP = make([]byte, gopp.IfElseInt(isip6, 16, 4))
	tmpbuf.Read(ipobj)
	// var ipobj net.IP = gopp.BytesReverse(ipbuf)
	var port uint16
	binary.Read(tmpbuf, binary.BigEndian, &port)
	addro := gopp.IfElse(istcp, &net.TCPAddr{Port: int(port), IP: ipobj}, &net.UDPAddr{Port: int(port), IP: ipobj}).(net.Addr)

	log.Println("node: ", i, len(data), addro.Network(), addro.String())
}

func (this *DHT) get_close_nodes(pubkey *CryptoKey, safamily uint8, islan, begood bool) (rets []*NodeFormat) {
	// get from this.CloseClientList
	// get from this.FriendsList
	// TODO more check

	tmplst := NewPriorityList(1000)
	this.CloseClientList.EachSnap(func(itemi PLItem) {
		tmplst.Put(itemi.(*ClientData))
	})

	this.FriendsList.EachSnap(func(itemi PLItem) {
		itemj := itemi.(*DHTFriend)
		itemj.ClientList.EachSnap(func(itemk PLItem) {
			tmplst.Put(itemk.(*ClientData))
		})
	})
	items := tmplst.SelectRandn(MAX_SENT_NODES)
	for _, itemx := range items {
		clidat := itemx.(*ClientData)
		node := &NodeFormat{Addr: clidat.Assoc.Addr, Pubkey: clidat.Pubkey}
		rets = append(rets, node)
	}
	// log.Printf("selected %d of %d\n", len(rets), tmplst.Len())
	return
}

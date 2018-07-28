package mintox

import (
	"encoding/binary"
	"gopp"
	"net"
)

const MAX_MOTD_LENGTH = 256 /* I recommend you use a maximum of 96 bytes. The hard maximum is this though. */
const INFO_REQUEST_PACKET_LENGTH = 78

type BootstrapInfo struct {
	Version uint32
	Motd    string
}

func (this *NetworkCore) handleInfoRequest(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	pktlen := 1 + 4 + len(this.bsinfo.Motd)
	buf := gopp.NewBufferBuf([]byte(gopp.RandStrHex(pktlen)))
	buf.WBufAt(0).WriteByte(BOOTSTRAP_INFO_PACKET_ID)
	binary.Write(buf.WBufAt(1), binary.BigEndian, this.bsinfo.Version)
	buf.WBufAt(1 + 4).Write([]byte(this.bsinfo.Motd))

	gopp.Assert(buf.Len() == pktlen, "buf error")
	return this.srv.WriteTo(buf.Bytes(), addr)
}

func (this *NetworkCore) BootstrapSetCallback(version uint32, motd string) bool {
	if len(motd) > MAX_MOTD_LENGTH {
		return false
	}

	this.bsinfo.Version = version
	this.bsinfo.Motd = motd

	this.RegisterHandle(BOOTSTRAP_INFO_PACKET_ID, this.handleInfoRequest, this)
	return true
}

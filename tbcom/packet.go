package tbcom

import (
	// "net"
	"reflect"
	"time"

	"github.com/kitech/gopp"
	"github.com/TokTok/go-toxcore-c"
	// log "github.com/sirupsen/logrus"

	"github.com/juju/ratelimit"

	"github.com/hashicorp/go-msgpack/codec"
	// "https://github.com/vmihailenco/msgpack"
)

// packet format type
const FT_MSGPACK = 1
const FT_CAPN = 2
const FT_BJSON = 3
const FT_GOJSON = 4 // []byte to base64
const FT_GOJSONV2 = 5 //

var fttype = FT_MSGPACK

func SetPacketFormat(fmttype int) int {
	old := fttype
	if fmttype>FT_MSGPACK&&fmttype<=FT_GOJSONV2 {
		fttype = fmttype
	}
	return old
}

type Packet struct {
	Conidc uint64
	Conids uint64
	Type  string // conn,close,ack,data,error
	Host   string
	Port int
	Errcode int
	Errmsg string
	Data []byte
}
// todo msgpack,capn,bjson,json

func (p *Packet) ToMsgpack(pfx byte) string {
	var mh codec.MsgpackHandle
	mh.MapType = reflect.TypeOf(map[string]any(nil))
	// mh.MapType = reflect.TypeOf(*p)
	var h = &mh

	var buf []byte
	enc := codec.NewEncoderBytes(&buf, h)
	err := enc.Encode(*p)
	gopp.ErrPrint(err)
	// log.Println(len(buf))

	return string([]byte{pfx}) + string(buf)
}

func (p *Packet) FromMsgpack(scc string) (byte, error) {

	var mh codec.MsgpackHandle
	mh.MapType = reflect.TypeOf(map[string]any(nil))
	// mh.MapType = reflect.TypeOf(*p)
	var h = &mh

	bcc := []byte(scc)
	dec := codec.NewDecoderBytes(bcc[1:], h)
	err := dec.Decode(p)

	return bcc[0], err
}

func NewClosePacket() {
}
func NewAckPacket() {
}

func (p *Packet) NewClosePacket() *Packet {
	return &Packet{Type:"close", Conidc:p.Conidc, Conids:p.Conids}
}
func (p *Packet) NewAckPacket(sid uint64) *Packet{
	return &Packet{Type:"ack", Conidc:p.Conidc, Conids:sid}
}

/////////////////

const ConnTimeo = 10*time.Second
const WriteTimeo = 20*time.Second
const ReadTimeo = 30*time.Second

// send rated and timeouted over toxtp
// global toxnet rate, not for per connection
type ToxRated struct {
	t *tox.Tox
	bkt *ratelimit.Bucket
}

const baserate = 10*1024 // 10KB/s
func NewToxRated(t *tox.Tox) *ToxRated {
	tra := &ToxRated{}
	tra.t = t
	tra.bkt = ratelimit.NewBucketWithRate(12*baserate, 10*baserate)
	return tra
}

func (tra *ToxRated) Send(frid uint32, data string) error {
	var t = tra.t
	var err error
	var retry int

	// tra.bkt.Take(int64(len(data)))
	err = t.FriendSendLosslessPacket(frid, data)
	if err == nil {
		tra.bkt.Wait(int64(len(data))/2) // = Take + Sleep
		return nil
	}
	tra.bkt.Wait(int64(len(data))) // = Take + Sleep

	// about 20s if all error
	for retry = 0; retry < 60; retry ++ {
		err = t.FriendSendLosslessPacket(frid, data)
		// gopp.ErrPrint(err, frid, "retry")
		if err == nil { break }
		if err.Error() == "error: 7" { // sendq full
		}
		time.Sleep(333*time.Millisecond)
	}
	gopp.ErrPrint(err, frid, "retry", retry)
	return err
}

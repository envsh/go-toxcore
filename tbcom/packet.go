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

type Packet struct {
	Conidc int
	Conids int
	Type  string // conn,close,ack,data,error
	Host   string
	Port int
	Errcode int
	Errmsg string
	Data []byte
}

func (p *Packet) ToMsgPack(pfx byte) string {
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

func (p *Packet) FromMsgPack(scc string) (byte, error) {

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

/////////////////

const ConnTimeo = 5*time.Second
const WriteTimeo = 5*time.Second
const ReadTimeo = 5*time.Second

// send rated and timeouted over toxtp
type ToxRated struct {
	t *tox.Tox
	bkt *ratelimit.Bucket
}

const baserate = 10*1024 // 10KB/s
func NewToxRated(t *tox.Tox) *ToxRated {
	tra := &ToxRated{}
	tra.t = t
	tra.bkt = ratelimit.NewBucketWithRate(5*baserate, 10*baserate)
	return tra
}

func (tra *ToxRated) Send(frid uint32, data string) error {
	// tra.bkt.Take(int64(len(data)))
	tra.bkt.Wait(int64(len(data))) // = Take + Sleep

	var t = tra.t
	var err error
	var retry int
	for retry = 0; retry < 30; retry ++ {
		err = t.FriendSendLosslessPacket(frid, data)
		// gopp.ErrPrint(err, frid, "retry")
		if err == nil { break }
		time.Sleep(233*time.Millisecond)
	}
	gopp.ErrPrint(err, frid, "retry", retry)
	return err
}

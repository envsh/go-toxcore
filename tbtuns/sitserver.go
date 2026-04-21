package tbtun

import (
	"fmt"
	// "io/ioutil"
	// "log"
	// "os"
	// "math/rand"
	// "strconv"
	// "strings"
	"time"
	"net"
	"errors"
	"sync/atomic"
	"sync"

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	"github.com/TokTok/go-toxcore-c"
	"github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	_ "go.uber.org/ratelimit"

)


/// demo bot
func init() {
	tbcom.Regit(newSitServer)
}

func newSitServer() *SitServer {
	b := &SitServer{}

	return b
}
type SitServer struct {
	outpkgs []any

	lsnport int // 2090

	tra *tbcom.ToxRated
}

func (this *SitServer) OnSelfConnectionStatus(t *tox.Tox, status int, userData any) {
	log.Println("hehhe", status)
}

func (this *SitServer) OnFriendMessage(t *tox.Tox, friendNumber uint32, message string, userData any) {
	log.Println("hehhe", message)
}

func (this *SitServer) OnFriendConnectionStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
	log.Println("hehhe", status)
}


func (this *SitServer) OnFriendLosslessPacket(t *tox.Tox, friendNumber uint32, data string, userData any) {
	// log.Println("<<<", len(data), data)
	// log.Println("<<<", friendNumber, len(data))

	// decode packet
	// if conn
	// if close
	// if data

	var pkto = &tbcom.Packet{}
	_, err := pkto.FromMsgpack(data)
	gopp.ErrPrint(err, "broken packet", len(data))
	if err != nil {
		return
	}
	if this.tra == nil {
		this.tra = tbcom.NewToxRated(t)
	}

	switch pkto.Type {
	case "conn":
		go func() {
			btime := time.Now()
			cs, err := this.doConn(pkto, t, friendNumber)
			gopp.ErrPrint(err)
			if err != nil { return }
			err = this.copyTcp2Tox(cs, t, friendNumber)
			log.Info("conn done", cs.cid, cs.sid, time.Since(btime).String())
		}()

	case "close":
		// close assoc tcp socket
		log.Println("closed by client", pkto.Conidc, pkto.Conids)
		connsmu.Lock()
		cs, ok := conns[pkto.Conids]
		connsmu.Unlock()

		if !ok {
			log.Error("not found", pkto.Conids)
		} else {
			cs.closec = true
			connsmu.Lock()
			delete(conns, pkto.Conids)
			delete(conns, cs.cid)
			connsmu.Unlock()
			cs.c.Close()
		}
	case "data":
		// forward to connected tcp socket
		connsmu.Lock()
		cs, ok := conns[pkto.Conids]
		connsmu.Unlock()

		if !ok {
			log.Error("not found", *pkto)
		} else {
			c := cs.c
			wn, err := c.Write(pkto.Data)
			gopp.ErrPrint(err, wn, c)
			// log.Info("xfer toxnet -> tcp", wn)
		}
	}
}

func (this *SitServer) doConn(pkto *tbcom.Packet, t *tox.Tox, friendNumber uint32) (*ConnState, error) {
	// connect to tunnel dest
	// save conn meta info
	// response ack

	log.Println("connto ...", pkto.Host, pkto.Port)
	c, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pkto.Host, pkto.Port))
	gopp.ErrPrint(err)

	var cs *ConnState
	rsperr := ""
	if err != nil {
		rsperr = err.Error()
	} else {
		cs = &ConnState{}
		cs.cid = pkto.Conidc
		cs.sid = atomic.AddUint64(&connid, 2)
		cs.conned = true
		cs.c = c

		connsmu.Lock()
		conns[pkto.Conidc] = cs
		conns[cs.sid] = cs
		connsmu.Unlock()

		log.Println("connected", pkto.Conidc, cs.sid, pkto.Host, pkto.Port)
		// go this.copyTcp2Tox(cs, t, friendNumber)

	}

	pkto.Type = "ack"
	pkto.Conidc = pkto.Conidc
	pkto.Errmsg = rsperr
	if cs != nil {
		gopp.Assert(cs.sid != 0, "")
		gopp.Assert(rsperr == "", rsperr)
		pkto.Conids = cs.sid
	}
	bcc := pkto.ToMsgpack(161)
	err = this.tra.Send(friendNumber, bcc)
	// err = t.FriendSendLosslessPacket(friendNumber, bcc)
	gopp.ErrPrint(err)

	if rsperr != "" {
		return nil, errors.New(rsperr)
	} else {
		return cs, nil
	}
}

func (this *SitServer) copyTcp2Tox(cs *ConnState, t *tox.Tox, friendNumber uint32) error {
	var tra = this.tra
	var c = cs.c
	var err error
	for {
		// read socket, forward toxtp
		var rdbuf = make([]byte, 999)
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn)
		if err != nil { break }

		// ratelimit send
		pkto3 := &tbcom.Packet{}
		pkto3.Type = "data"
		pkto3.Conidc = cs.cid
		pkto3.Conids = cs.sid
		pkto3.Data = rdbuf[:rn]
		scc := pkto3.ToMsgpack(161)

		err = tra.Send(friendNumber, scc)
		gopp.ErrPrint(err)
		// log.Info("xfer tcp -> toxnet", rn, err == nil)
		if err != nil { break }

	}
	cs.closes = true
	if true && !cs.closec {
		pkto3 := &tbcom.Packet{}
		pkto3.Type = "close"
		pkto3.Conidc = cs.cid
		pkto3.Conids = cs.sid
		// pkto3.Data = rdbuf[:rn]
		scc := pkto3.ToMsgpack(161)

		err = tra.Send(friendNumber, scc)
		gopp.ErrPrint(err)
	}

	return nil
}

/////////////

type TcpWriter struct {
	t      *tox.Tox
	frnum  uint32
}

/////////////

var connid uint64 = 8 // step 2 and %2==0
var conns = make(map[uint64]*ConnState)
var connsmu = sync.RWMutex{}

type ConnState struct {
	cid  uint64 // %2 == 1
	sid  uint64 // %2 == 0
	c   net.Conn
	// ch chan *tbcom.Packet
	conned bool
	closec bool
	closes bool
}

package tbtun

import (
	"fmt"
	// "io/ioutil"
	// "log"
	// "os"
	// "math/rand"
	// "strconv"
	// "strings"
	// "time"
	"net"

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
	_, err := pkto.FromMsgPack(data)
	gopp.ErrPrint(err, "broken packet", len(data))
	if err != nil {
		return
	}

	switch pkto.Type {
	case "conn":

		// connect to tunnel dest
		// save conn meta info
		// response ack

		log.Println("connto ...", pkto.Host, pkto.Port)
		c, err := net.Dial("tcp", fmt.Sprintf("%s:%d", pkto.Host, pkto.Port))
		gopp.ErrPrint(err)

		cs := &ConnState{}
		rsperr := ""
		if err != nil {
			rsperr = err.Error()
		} else {
			cs.cid = pkto.Conidc
			connid += 2
			cs.sid = connid
			cs.conned = true
			cs.c = c
			conns[pkto.Conidc] = cs
			conns[cs.sid] = cs

			log.Println("connected", pkto.Conidc, cs.sid, pkto.Host, pkto.Port)
			tra := tbcom.NewToxRated(t)
			go func(){
				for {
					// read socket, forward toxtp
					var rdbuf = make([]byte, 999)
					rn, err := c.Read(rdbuf)
					gopp.ErrPrint(err, rn)
					if err != nil { break }

					// ratelimit send
					pkto3 := &tbcom.Packet{}
					pkto3.Type = "data"
					pkto3.Conidc = pkto.Conidc
					pkto3.Conids = cs.sid
					pkto3.Data = rdbuf[:rn]
					scc := pkto3.ToMsgPack(161)

					err = tra.Send(friendNumber, scc)
					gopp.ErrPrint(err)
					// log.Info("xfer tcp -> toxnet", rn, err == nil)
					if err != nil { break }

				}
				cs.closes = true
				if true && !cs.closec {
					pkto3 := &tbcom.Packet{}
					pkto3.Type = "close"
					pkto3.Conidc = pkto.Conidc
					pkto3.Conids = cs.sid
					// pkto3.Data = rdbuf[:rn]
					scc := pkto3.ToMsgPack(161)

					err = tra.Send(friendNumber, scc)
					gopp.ErrPrint(err)
				}
			}()

		}

		gopp.Assert(cs.sid != 0, "")
		pkto.Type = "ack"
		pkto.Conidc = pkto.Conidc
		pkto.Conids = cs.sid
		pkto.Errmsg = rsperr
		bcc := pkto.ToMsgPack(161)
		err = t.FriendSendLosslessPacket(friendNumber, bcc)
		gopp.ErrPrint(err)

	case "close":
		// close assoc tcp socket
		log.Println("closed by client", pkto.Conidc, pkto.Conids)
		cs, ok := conns[pkto.Conids]
		if !ok {
			log.Error("not found", pkto.Conids)
		} else {
			cs.closec = true
			delete(conns, pkto.Conids)
			delete(conns, cs.cid)
			cs.c.Close()
		}
	case "data":
		// forward to connected tcp socket
		cs, ok := conns[pkto.Conids]
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

var connid = 8 // step 2 and %2==0
var conns = make(map[int]*ConnState)

type ConnState struct {
	cid  int // %2 == 1
	sid  int // %2 == 0
	c   net.Conn
	// ch chan *tbcom.Packet
	conned bool
	closec bool
	closes bool
}

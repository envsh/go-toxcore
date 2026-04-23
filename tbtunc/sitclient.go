package tbtunc

import (
	// "fmt"
	// "io/ioutil"
	// "log"
	// "os"
	// "math/rand"
	// "strconv"
	// "strings"
	// "time"

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
	tbcom.Regit(newSitClient)
}

func newSitClient() *SitClient {
	b := &SitClient{}
	return b
}
type SitClient struct {
	outpkgs []any

	lsnport int // 2090
}

func (this *SitClient) OnSelfConnectionStatus(t *tox.Tox, status int, userData any) {
	log.Println("hehhe", status)
}

func (this *SitClient) OnFriendMessage(t *tox.Tox, frnum uint32, message string, userData any) {
	log.Println("hehhe", message)
}

func (this *SitClient) OnFriendConnectionStatus(t *tox.Tox, frnum uint32, status int, userData any) {
	log.Println("hehhe", frnum, status)
}

func (this *SitClient) OnFriendLosslessPacket(t *tox.Tox, frnum uint32, data string, userData any) {
	// log.Println(len(data), frnum, data)
	// log.Println("<<<", len(data), frnum)
	// decode packet

	// // if conn
	// if ack
	// if close
	// if data

	var pkto = &tbcom.Packet{}
	_, err := pkto.FromMsgpack(data)
	gopp.ErrPrint(err)
	// log.Println(pkto.Type, pkto.Conidc)
	if err != nil {
		log.Error("borken packet", len(data))
	}
	connst, connok := connings[pkto.Conidc]
	if !connok {
		log.Warn("not found", pkto.Conidc)
		// return
	}

	switch pkto.Type {
	case "conn":
	// 	pkto.Type = "ack"
	// 	bcc := pkto.ToMsgPack(161)
	// 	err = t.FriendSendLosslessPacket(friendNumber, bcc)
	// 	gopp.ErrPrint(err)
	case "ack":
		log.Println("conn acked", pkto.Conidc, pkto.Conids)

		if connok {
			connst.ch <- pkto
		} else {
			log.Println("maybe timeout")
		}
	case "close":
		if !connok { break }

		delete(connings, pkto.Conidc)
		connst.c.Close()
		close(connst.ch)
		connst.closes = true

	case "data":
		if !connok { break }
		//
		c := connst.c
		wn, err := c.Write(pkto.Data)
		gopp.ErrPrint(err, wn)
		// log.Info("xfer toxnet -> tcp", wn, len(data))

		connst.dlsize += int64(wn)
		gstats.dlsize += int64(wn)
	}

}

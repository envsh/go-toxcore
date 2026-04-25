package tbtunc

import (
	"net"
	// "reflect"
	"fmt"
	"os"
	"time"
	"sync/atomic"
	"flag"
	"io/ioutil"
	"encoding/json"
	"path/filepath"

	"github.com/kitech/gopp"
	"github.com/envsh/toxera/tbcom"
	log "github.com/sirupsen/logrus"

	 // "github.com/juju/ratelimit"

	// "github.com/hashicorp/go-msgpack/codec"
)

type Config struct {
	Port  int // 2090, socks protocol
	Host  string // "", "*", "0.0.0.0"
	Peerid string // toxid of server
	ToxFile string
	CfgDir  string
	CfgFile string
	Debug  bool

	PeerHost string
	PeerPort int
}

var dftcfg = func() Config{
	cfg := Config{}
	cfg.Port = 2090
	cfg.Host = "127.0.0.1"
	cfg.CfgFile = "tbtuncli.json"
	cfg.ToxFile = "toxsave.data"
	cfg.PeerHost = "127.0.0.1"
	cfg.PeerPort = 9996
	return cfg
}()
var gcfg = dftcfg

func (c Config) ToxFilePath() string {
	if c.CfgDir=="" {
		return c.ToxFile
	}
	return filepath.Join(c.CfgDir, c.ToxFile)
}

// cmdline > cfgfile > dft
func cmdflagConfig() {
	flag.StringVar(&gcfg.CfgDir, "cfgdir", gcfg.CfgDir, "cfg dir")
	flag.StringVar(&gcfg.CfgFile, "cfgfile", gcfg.CfgFile, "cfg file")

	// try load config file first
	cfgfile := gcfg.CfgFile
	if gcfg.CfgFile != "" {
		cfgfile = filepath.Join(gcfg.CfgDir, gcfg.CfgFile)
	}
	bcc, err := ioutil.ReadFile(cfgfile)
	if err == nil {
		// merge cfg
		cfgtmp := Config{}
		err = json.Unmarshal(bcc, &cfgtmp)
		gopp.ErrPrint(err)
		gcfg = cfgtmp
	}

	flag.IntVar(&gcfg.Port, "port", gcfg.Port, "local listen socks port")
	flag.StringVar(&gcfg.Host, "host", gcfg.Host, "local listen socks IP")
	flag.StringVar(&gcfg.Peerid, "toxid", gcfg.Peerid, "server toxid 72B ABCDEF0123")
	flag.StringVar(&gcfg.ToxFile, "toxfile", gcfg.ToxFile, "tox save file")
	flag.BoolVar(&gcfg.Debug, "debug", gcfg.Debug, "debug flag")

	flag.IntVar(&gcfg.PeerPort, "rport", gcfg.PeerPort, "remote listen socks port")
	flag.StringVar(&gcfg.PeerHost, "rhost", gcfg.PeerHost, "remote listen socks IP")

	flag.Parse()
	{
		// save file
		bcc, err = json.MarshalIndent(gcfg, "", "    ")
		err = gopp.SafeWriteFile(cfgfile, bcc, 0644)
		gopp.ErrPrint(err, cfgfile, len(bcc))
		if err != nil { os.Exit(-1) }
	}
}

func chkflagConfig() {
	if gcfg.Peerid == "" {
		flag.Usage()
		log.Fatalln("peerid must set")
	}
}

///////
func run_tcp_server() {
	addr := fmt.Sprintf("%s:%d", gcfg.Host, gcfg.Port)
	lsner, err := net.Listen("tcp", addr)
	gopp.ErrPrint(err, addr)
	if err != nil {
		log.Fatalln(err.Error(), addr)
	}
	log.Info("Listen on socks://", addr)

	for {
		c, err := lsner.Accept()
		gopp.ErrPrint(err, c)
		log.Println("accepted tcp", c)
		go serv_tcp_conn(c)
	}
}

var connid uint64 = 9 // step 2
var connings = make(map[uint64]*ConnState)
var	tptra *tbcom.ToxRated // := tbcom.NewToxRated(t)


func newConnState(cid uint64, c net.Conn) *ConnState {
	ch := make(chan *tbcom.Packet, 8)
	cs := &ConnState{}
	cs.cid = cid
	cs.c = c
	cs.ch = ch

	cs.lastRecvTM = time.Now()
	return cs
}

type ConnState struct {
	cid  uint64
	c   net.Conn
	ch chan *tbcom.Packet
	transportid string // WIP toxid now
	conned bool
	closec bool
	closes bool

	//
	lastRecvTM  time.Time
	dlsize int64
	upsize int64
}

var gstats = struct {
	dlsize int64
	upsize int64
}{}

func serv_tcp_conn(c net.Conn) {
	var peerid = gcfg.Peerid
	defer c.Close()

	// send over toxnet
	t := gettox()
	if t == nil {
		log.Println("toxobj nil")
		return
	}
	if tptra == nil {
		tptra = tbcom.NewToxRated(t)
	}
	gopp.Assert(tptra != nil, "tptra nil")
	var tra = tptra

	cid := atomic.AddUint64(&connid, 2)
	// cs := &ConnState{cid, c, ch, false, false, false, 0, 0}
	cs := newConnState(cid, c)
	connings[cid] = cs

	frid, err := t.FriendByPublicKey(peerid)
	gopp.ErrPrint(err)
	pkt1 := string([]byte{161}) + "connect..."

	var pkto = &tbcom.Packet{}
	pkto.Type = "conn"
	pkto.Data = []byte("dattt")
	pkto.Conidc = cid
	pkto.Host = gcfg.PeerHost // "127.0.0.1"
	pkto.Port = gcfg.PeerPort // 9996

	pkt1 = pkto.ToMsgpack(161)
	if true {
		pkto2 := &tbcom.Packet{}
		p2, err := pkto2.FromMsgpack(pkt1)
		log.Info(*pkto2, p2, err, *pkto)
	}
	log.Info("sending ...", len(pkt1))
	// err = t.FriendSendLosslessPacket(frid, pkt1)
	err = tra.Send(frid, pkt1)
	gopp.ErrPrint(err, frid)
	if err != nil {
		return
	}

	// if recv handshake then goon
	var connbtime = time.Now()
	var ackpkt *tbcom.Packet
	select {
	case rpkt := <- cs.ch:
		log.Println("conned", rpkt)
		if rpkt == nil {
			return
		}
		if rpkt.Errmsg != "" {
			return
		}
		if rpkt.Conids % 2 != 0 {
			log.Warn("Invalid Conids", rpkt.Conids)
		}
		ackpkt = rpkt
		cs.conned = true
	case <- time.After(9*time.Second):
		log.Warn("conn timeout...", cs.cid, time.Since(connbtime))
		delete(connings, cid)
		return
	}

	// check recv timeout
	go func() {
		for {
			time.Sleep(3*time.Second)
			dur := time.Since(cs.lastRecvTM)
			if dur < tbcom.ReadTimeo {
				continue
			}
			log.Warn("== read timeout", cs.cid, cs.closec, cs.closes, dur)
			if (cs.closec || cs.closes) { break }
			if dur > tbcom.ReadTimeo*2/3 {
				// think it as closed
				if !cs.closec {
					cs.c.Close()
				}
				break
			}
		}
	}()

	// read tcp
	var rdbuf = make([]byte, 999)
	for {
		rn, err := c.Read(rdbuf)
		gopp.ErrPrint(err, rn)
		if err != nil { break }

		pkto3 := &tbcom.Packet{}
		pkto3.Type = "data"
		pkto3.Conidc = cid
		pkto3.Conids = ackpkt.Conids
		pkto3.Data = rdbuf[:rn]
		scc := pkto3.ToMsgpack(161)

		err = tra.Send(frid, scc)
		gopp.ErrPrint(err, "send timeout", len(scc))
		// log.Info("xfer tcp -> toxnet", rn)
		cs.upsize += int64(len(scc))
		gstats.upsize += int64(len(scc))
	}
	log.Info("for done", c, cs.cid)

	if cs.closes {
	} else {
		cs.closec = true
		delete(connings, cs.cid)

		// send close packet
		pkto3 := &tbcom.Packet{}
		pkto3.Type = "close"
		pkto3.Conidc = pkto.Conidc
		pkto3.Conids = ackpkt.Conids
		// pkto3.Data = rdbuf[:rn]
		scc := pkto3.ToMsgpack(161)

		err = tra.Send(frid, scc)
		gopp.ErrPrint(err)
	}

	log.Info("func done", c, cs.cid, "dl", cs.dlsize, "up", cs.upsize)
}

func onIncomingPacket(scc string) {

}

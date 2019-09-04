package xtox

import (
	"encoding/json"
	"log"
	"math/rand"
	"sort"
	"sync"
	"time"

	simplejson "github.com/bitly/go-simplejson"
	// tox "github.com/kitech/go-toxcore"
	tox "github.com/TokTok/go-toxcore-c"
)

// settable
var EnablePing = true
var ndp = newNodePool()

type NodePool struct {
	sync.RWMutex
	allNodes  []ToxNode
	currNodes [3]ToxNode
	grpNodes  map[string][]ToxNode
}

func newNodePool() *NodePool {
	this := &NodePool{}
	this.allNodes = []ToxNode{}
	this.grpNodes = map[string][]ToxNode{}
	return this
}

// empty => default
func Bootstrap(t *tox.Tox, grp string) {
	node := get1node(grp)
	bootstrapFrom(t, node)
}
func bootstrapFrom(t *tox.Tox, node ToxNode) {
	r1, err := t.Bootstrap(node.Ipaddr, node.Port, node.Pubkey)
	if node.status_tcp {
		r2, err := t.AddTcpRelay(node.Ipaddr, node.Port, node.Pubkey)
		log.Println("bootstrap(tcp):", r1, err, r2, node.Ipaddr, node.last_ping, node.status_tcp)
	} else {
		log.Println("bootstrap(udp):", r1, err, node.Ipaddr,
			node.last_ping, node.status_tcp, node.last_ping_rt)
	}
}

// 切换到其他的bootstrap nodes上
func switchServer(t *tox.Tox) {
	newNodes := get3nodes()
	for _, node := range newNodes {
		bootstrapFrom(t, node)
	}
	ndp.currNodes = newNodes
}

func get3nodes() (nodes [3]ToxNode) {
	idxes := make(map[int]bool, 0)
	currips := make(map[string]bool, 0)
	for idx := 0; idx < len(ndp.currNodes); idx++ {
		currips[ndp.currNodes[idx].Ipaddr] = true
	}
	for n := 0; n < len(ndp.allNodes)*3; n++ {
		idx := rand.Int() % len(ndp.allNodes)
		_, ok1 := idxes[idx]
		_, ok2 := currips[ndp.allNodes[idx].Ipaddr]
		if !ok1 && !ok2 && ndp.allNodes[idx].status_tcp == true && ndp.allNodes[idx].last_ping_rt > 0 {
			idxes[idx] = true
			if len(idxes) == 3 {
				break
			}
		}
	}
	if len(idxes) < 3 {
		// errl.Println("can not find 3 new nodes:", idxes)
	}

	_idx := 0
	for k, _ := range idxes {
		nodes[_idx] = ndp.allNodes[k]
		_idx += 1
	}
	return
}
func get1node(grp string) ToxNode {
	nodes, ok := ndp.grpNodes[grp]
	if !ok {
		nodes = ndp.allNodes
	}
	idx := int(rand.Uint32() % uint32(len(nodes)))
	return nodes[idx]
}

func init() {
	rand.Seed(time.Now().UnixNano())
	initToxNodes()
	go pingNodesLoop()
}

// fixme: chown root.root toxtun-go && chmod u+s toxtun-go
// setcap cap_net_raw=+ep /bin/goping-binary
// should block
func pingNodesLoop() {
	stop := false
	for !stop {
		if EnablePing {
			pingNodes()
		}
		// TODO longer ping interval
		time.Sleep(300 * time.Second)
	}
}
func pingNodes() {
	btime := time.Now()
	errcnt := 0
	var errs = make(map[string]int)
	for idx, node := range ndp.allNodes {
		if false {
			log.Println(idx, node)
		}
		if true {
			// rtt, err := Ping0(node.ipaddr, 3)
			rtt, err := Ping2(node.Ipaddr, 3)
			if err != nil {
				// log.Println("ping", ok, node.ipaddr, rtt.String())
				// log.Println("ping", err, node.ipaddr, rtt.String())
				errcnt += 1
				if _, ok := errs[err.Error()]; ok {
					errs[err.Error()] += 1
				} else {
					errs[err.Error()] = 1
				}
			}
			if err == nil {
				ndp.allNodes[idx].last_ping_rt = uint(time.Now().Unix())
				ndp.allNodes[idx].rtt = rtt
			} else {
				ndp.allNodes[idx].last_ping_rt = uint(0)
				ndp.allNodes[idx].rtt = time.Duration(0)
			}
		}
	}
	etime := time.Now()
	log.Printf("Pinged all=%d, errcnt=%d, %v, %d, %+v\n",
		len(ndp.allNodes), errcnt, etime.Sub(btime), len(errs), errs)
}

func AddNode(pkey string, ip string, port int, tcp_ports ...int) {
	n := ToxNode{}
	n.Pubkey = pkey
	n.Ipaddr = ip
	n.Port = uint16(port)
	for _, port := range tcp_ports {
		n.Tcp_ports = append(n.Tcp_ports, uint16(port))
	}
	n.status_tcp = len(tcp_ports) > 0
	n.isthird = true
	ndp.allNodes = append(ndp.allNodes, n)
}
func ExportNodes() string {
	bcc, err := json.Marshal(ndp.allNodes)
	if err != nil {
		log.Panicln("wtf", err)
	}
	return string(bcc)
}

func initToxNodes() {
	bcc, err := Asset("toxnodes.json")
	if err != nil {
		log.Panicln(err)
	}
	jso, err := simplejson.NewJson(bcc)
	if err != nil {
		log.Panicln(err)
	}

	nodes := jso.Get("nodes").MustArray()
	for idx := 0; idx < len(nodes); idx++ {
		nodej := jso.Get("nodes").GetIndex(idx)
		/*
			log.Println(idx, nodej.Get("ipv4"), nodej.Get("port"), nodej.Get("last_ping"),
				len(nodej.Get("tcp_ports").MustArray()))
		*/
		node := ToxNode{
			Ipaddr:       nodej.Get("ipv4").MustString(),
			Port:         uint16(nodej.Get("port").MustUint64()),
			Pubkey:       nodej.Get("public_key").MustString(),
			last_ping:    uint(nodej.Get("last_ping").MustUint64()),
			status_tcp:   nodej.Get("status_tcp").MustBool(),
			last_ping_rt: uint(time.Now().Unix()),
			weight:       calcNodeWeight(nodej),
		}

		ndp.allNodes = append(ndp.allNodes, node)
		if idx < len(ndp.currNodes) {
			ndp.currNodes[idx] = node
		}
	}

	sort.Sort(ByRand(ndp.allNodes))
	for idx, node := range ndp.allNodes {
		if false {
			log.Println(idx, node.Ipaddr, node.Port, node.last_ping)
		}
	}
	log.Println("Load nodes:", len(ndp.allNodes))
}

func calcNodeWeight(nodej *simplejson.Json) int {
	return 0
}

type ToxNode struct {
	isthird    bool
	Ipaddr     string
	Port       uint16 // udp port
	Tcp_ports  []uint16
	Pubkey     string
	weight     int
	usetimes   int
	legacy     int
	chktimes   int
	last_ping  uint
	status_tcp bool
	///
	last_ping_rt uint // 程序内ping的时间
	rtt          time.Duration
}

type ByRand []ToxNode

func (this ByRand) Len() int           { return len(this) }
func (this ByRand) Swap(i, j int)      { this[i], this[j] = this[j], this[i] }
func (this ByRand) Less(i, j int) bool { return rand.Int()%2 == 0 }

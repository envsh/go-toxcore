package xtox

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
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
	grpNodes  map[string][]ToxNode // group =>
}

func newNodePool() *NodePool {
	this := &NodePool{}
	this.allNodes = []ToxNode{}
	this.grpNodes = map[string][]ToxNode{}
	return this
}

// bootstrap and connect tcp relay
// empty grp => default
func Bootstrap(t *tox.Tox, grp string) error {
	node := get1node(grp)
	err := BootstrapFromNode(t, node)
	return err
}
func BootstrapFromNode(t *tox.Tox, node ToxNode) error {
	if node.Ipaddr == "" || node.Pubkey == "" {
		log.Println("wtf empty node")
		return nil
	}
	r1, err := t.Bootstrap(node.Ipaddr, node.Port, node.Pubkey)
	if node.status_tcp {
		r2, err1 := t.AddTcpRelay(node.Ipaddr, node.Port, node.Pubkey)
		log.Println("bootstrap(tcp):", r1, err1, r2, node.Ipaddr, node.last_ping, node.status_tcp)
		if err1 != nil {
			err = err1
		}
	} else {
		log.Println("bootstrap(udp):", r1, err, node.Ipaddr,
			node.last_ping, node.status_tcp, node.last_ping_rt)
	}
	return err
}

// 切换到其他的bootstrap nodes上
func SwitchServer(t *tox.Tox, grp string) error {
	var err error
	newNodes := get3nodes(grp)
	// log.Println(len(newNodes), len(ndp.grpNodes[grp]), len(ndp.allNodes), newNodes)
	for _, node := range newNodes {
		err1 := BootstrapFromNode(t, node)
		if err1 != nil {
			err = err1
		}
	}
	ndp.currNodes = newNodes
	return err
}

func get3nodes(grp string) (nodes [3]ToxNode) {
	srcnodes := []ToxNode{}
	if grp != "" {
		srcnodes = ndp.grpNodes[grp]
	} else {
		srcnodes = ndp.allNodes
	}
	return get3nodesFrom(srcnodes)
}
func get3nodesFrom(srcnodes []ToxNode) (nodes [3]ToxNode) {
	idxes := make(map[int]bool, 0)
	currips := make(map[string]bool, 0)
	// for idx := 0; idx < len(srcnodes); idx++ {
	//	currips[srcnodes[idx].Ipaddr] = true
	//}

	for n := 0; n < len(srcnodes)*3; n++ {
		idx := rand.Int() % len(srcnodes)
		_, ok1 := idxes[idx]
		_, ok2 := currips[srcnodes[idx].Ipaddr]
		// log.Println(ok1, ok2, srcnodes[idx].status_tcp, srcnodes[idx].last_ping_rt > 0)
		if !ok1 && !ok2 && srcnodes[idx].status_tcp == true { // && srcnodes[idx].last_ping_rt > 0 {
			idxes[idx] = true
			if len(idxes) == 3 {
				break
			}
		}
	}
	if len(idxes) == 0 {
		log.Println("Cannot find 3 new nodes:", idxes)
	}
	if len(idxes) < 3 {
		// log.Println("Cannot find 3 new nodes:", idxes)
		// errl.Println("Cannot find 3 new nodes:", idxes)
	}

	_idx := 0
	for k, _ := range idxes {
		nodes[_idx] = srcnodes[k]
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

// empty grp to default
func AddNode(pkey string, ip string, port int, grp string, tcp_ports ...int) {
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
	if grp != "" {
		ndp.grpNodes[grp] = append(ndp.grpNodes[grp], n)
	}
}
func DelNodeByIPPort(ip string, port int, grp string) {
	nodes := ndp.allNodes
	if grp != "" {
		nodes = ndp.grpNodes[grp]
	}
	newnodes := []ToxNode{}
	for _, n := range nodes {
		if n.Ipaddr == ip && int(n.Port) == port {
			continue
		}
		newnodes = append(newnodes, n)
	}
	if grp != "" {
		ndp.grpNodes[grp] = newnodes
	} else {
		ndp.allNodes = newnodes
	}
}
func DelNodeByPubkey(pubkey string, grp string) {
	nodes := ndp.allNodes
	if grp != "" {
		nodes = ndp.grpNodes[grp]
	}
	newnodes := []ToxNode{}
	for _, n := range nodes {
		if n.Pubkey == pubkey {
			continue
		}
		newnodes = append(newnodes, n)
	}
	if grp != "" {
		ndp.grpNodes[grp] = newnodes
	} else {
		ndp.allNodes = newnodes
	}
}
func ExportNodes(grp string) []ToxNode {
	nodes := ndp.grpNodes[grp]
	return nodes
}
func ExportNodesJson() string {
	bcc, err := json.Marshal(ndp.allNodes)
	if err != nil {
		log.Panicln("wtf", err)
	}
	return string(bcc)
}
func RefreshHttpRemoteNodes(pxy string) error {
	resp, err := http.Get("https://nodes.tox.chat/json")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	bcc, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	err = parseNodesData(bcc)
	return err
}

var bsnodesfile = "toxbsnodes.json"

func initToxNodes() {
	bcc, err := Asset("toxbsnodes.json")
	if err != nil {
		log.Panicln(err)
	}
	err = parseNodesData(bcc)
	if err != nil {
		log.Panicln(err)
	}
}
func parseNodesData(bcc []byte) error {
	jso, err := simplejson.NewJson(bcc)
	if err != nil {
		return err
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
	return nil
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

func (n ToxNode) Weight() int {
	return n.weight
}
func (n ToxNode) Rttms() int {
	return int(n.rtt.Nanoseconds() / 1000000)
}
func (n ToxNode) IsRelay() bool {
	return n.status_tcp
}
func (n ToxNode) LastSeen() time.Time {
	return time.Unix(int64(n.last_ping), 0)
}
func (n ToxNode) String() string {
	return fmt.Sprintf("%s:%d:%s", n.Ipaddr, n.Port, n.Pubkey)
	// libp2p's Multiaddr format???
	// /ip4/ip/tcp/port/key
	// /ip4/ip/udp/port/key
}
func NewToxNodeFrom(ipportpubkey string) (n ToxNode, err error) {
	parts := strings.Split(ipportpubkey, ":")
	if len(parts) != 3 {
		return n, os.ErrInvalid
	}
	if !CheckPubkey(parts[2]) {
		return n, os.ErrInvalid
	}
	iport, err := strconv.Atoi(parts[1])
	if err != nil {
		return n, err
	}

	n.Pubkey = parts[2]
	n.Port = uint16(iport)
	n.Ipaddr = parts[0]

	return
}

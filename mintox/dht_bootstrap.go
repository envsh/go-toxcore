package mintox

import (
	"crypto/sha256"
	"gopp"
	"log"
	"time"
)

func MainBootstrapNode() {
	bsnodeo := NewBootstrapNode()
	bsnodeo.Start()
	go func() {
		time.Sleep(3 * time.Second)
		host, pubkeyh := bsnodes[4], bsnodes[5]
		log.Println(host, pubkeyh)
		err := bsnodeo.dhto.BootstrapFromAddr(host, pubkeyh)
		gopp.ErrPrint(err)
	}()
	select {}
}

type BootstrapNode struct {
	is_waiting_for_dht_connection bool

	PORT  uint16   // udp
	ports []uint16 // tcp

	seckey  *CryptoKey
	pubkey  *CryptoKey
	dhto    *DHT
	tcpsrvo *TCPServer

	// oniono *Onion
	// landiso *LanDiscovery
}

func NewBootstrapNode() *BootstrapNode {
	this := &BootstrapNode{}
	this.is_waiting_for_dht_connection = true
	this.setInitVars()
	return this
}

func (this *BootstrapNode) setInitVars() {
	this.PORT = 54432
	this.ports = []uint16{this.PORT, 4433, 3389}
	binskca := sha256.Sum256([]byte("TODO tox bootstrap node secret key"))
	this.seckey = NewCryptoKey(binskca[:])
	this.pubkey = CBDerivePubkey(this.seckey)
}

func (this *BootstrapNode) Start() {
	log.Println("Listen on:", "UDP:", this.PORT, "TCP:", this.ports)
	log.Println("DHT Public key:", this.pubkey.ToHex())

	this.dhto = NewDHT()
	this.dhto.SetKeyPair(this.pubkey, this.seckey)
	// onion

	this.dhto.Neto.BootstrapSetCallback(1, "This is a test motd of pgobs")

	this.tcpsrvo = NewTCPServer(this.ports, this.seckey, nil)
	this.tcpsrvo.Start()

	// dht bootstrap

	// lan discovery

}

//////
type NodeAddr struct {
	PublicKey string `json:"public_key,omitempty"`
	IPv4      string `json:"ipv4,omitempty"`
	Port      uint16 `json:"port,omitempty"`       // udp
	StatusUDP bool   `json:"status_udp,omitempty"` // udp

	TCPPorts  []uint16 `json:"tcp_ports,omitempty"`
	TCPStatus []bool
	StatusTCP bool `json:"status_tcp,omitempty"`

	IPv6 string `json:"ipv6,omitempty"`

	LastPing   int64  `json:"last_ping,omitempty"`
	Version    string `json:"version,omitempty"`
	Motd       string `json:"motd,omitempty"`
	Location   string `json:"location,omitempty"`
	Maintainer string `json:"maintainer,omitempty"`
}

func (this *NodeAddr) SupportTCP() bool { return len(this.TCPPorts) > 0 }

package main

import (
	"net"
	"sync"
	"time"
)

const TCP_CONN_NONE = 0
const TCP_CONN_VALID = 1

/* NOTE: only used by TCP_con */
const TCP_CONN_CONNECTED = 2

/* Connection is not connected but can be quickly reconnected in case it is needed. */
const TCP_CONN_SLEEPING = 3

const TCP_CONNECTIONS_STATUS_NONE = 0
const TCP_CONNECTIONS_STATUS_REGISTERED = 1
const TCP_CONNECTIONS_STATUS_ONLINE = 2

const MAX_FRIEND_TCP_CONNECTIONS = 6

/* Time until connection to friend gets killed (if it doesn't get locked withing that time) */
const TCP_CONNECTION_ANNOUNCE_TIMEOUT = (TCP_CONNECTION_TIMEOUT)

/* The amount of recommended connections for each friend
   NOTE: Must be at most (MAX_FRIEND_TCP_CONNECTIONS / 2) */
const RECOMMENDED_FRIEND_TCP_CONNECTIONS = (MAX_FRIEND_TCP_CONNECTIONS / 2)

/* Number of TCP connections used for onion purposes. */
const NUM_ONION_TCP_CONNECTIONS = RECOMMENDED_FRIEND_TCP_CONNECTIONS

// To Friend's connections
// 1:MAX_FRIEND_TCP_CONNECTIONS
// type TCPFriendCon
type TCPConnectionTo struct {
	Status uint8
	Pubkey *CryptoKey

	Conns [MAX_FRIEND_TCP_CONNECTIONS]struct {
		Conn   uint32 // ???
		Status uint
		Connid uint
	}

	Cbid int // id used in callbacks
}

// To RelayPK's TCPClient connections
// 1:N
// type TCPClientCon ???
// type TCPRelayCon ???
type TCPCon struct {
	Status uint8

	TCPClientConns []*TCPClient // TCP_Client_Connection *connection;
	ConnectedTime  time.Time
	LockCount      uint32
	SleepCount     uint32
	Onion          bool

	/* Only used when connection is sleeping. */
	Addr    net.Addr
	RelayPK *CryptoKey
	Unsleep bool /* set to 1 to unsleep connection. */
}

// 1:N
type TCPConnections struct {
	dhto *DHT

	SelfPubkey *CryptoKey
	SelfSekkey *CryptoKey

	connmu   sync.RWMutex
	ConnTos  []*TCPConnectionTo
	TCPConns []*TCPCon

	TCPDataFunc   func(object Object, cbid int, data []byte, cbdata Object) int
	TCPDataCbdata Object

	TCPOOBFunc   func(object Object, pubkey *CryptoKey, tcp_connections_number uint, data []byte, cbdata Object) int
	TCPOOBCbdata Object

	TCPOnionFunc   func(object Object, data []byte, cbdata Object) int
	TCPOnionCbdata Object

	// TCP_Proxy_Info proxy_info;

	OnionStatus   bool
	OnionNumConns uint16
}

func NewTCPConnections(seckey *CryptoKey) *TCPConnections {
	this := &TCPConnections{}
	pubkey := CBDerivePubkey(seckey)
	this.SelfPubkey, this.SelfSekkey = pubkey, seckey

	this.ConnTos = make([]*TCPConnectionTo, 0)
	this.TCPConns = make([]*TCPCon, 0)

	return this
}

package mintox

import (
	"net"
	"time"
)

/* Change symmetric keys every 2 hours to make paths expire eventually. */
const KEY_REFRESH_INTERVAL = (2 * 60 * 60)

type Onion struct {
	dhto      *DHT
	neto      *NetworkCore
	secsymkey *CryptoKey
	timestamp time.Time

	shrkeys1 [256 * MAX_KEYS_PER_SLOT]*SharedKey
	shrkeys2 [256 * MAX_KEYS_PER_SLOT]*SharedKey
	shrkeys3 [256 * MAX_KEYS_PER_SLOT]*SharedKey

	recv1func func(Object, addr net.Addr, data []byte)
	cbdata    Object
}

//

const ONION_MAX_PACKET_SIZE = 1400

const ONION_RETURN_1 = (NONCE_SIZE + SIZE_IPPORT + MAC_SIZE)
const ONION_RETURN_2 = (NONCE_SIZE + SIZE_IPPORT + MAC_SIZE + ONION_RETURN_1)
const ONION_RETURN_3 = (NONCE_SIZE + SIZE_IPPORT + MAC_SIZE + ONION_RETURN_2)

const ONION_SEND_BASE = (PUBLIC_KEY_SIZE + SIZE_IPPORT + MAC_SIZE)
const ONION_SEND_3 = (NONCE_SIZE + ONION_SEND_BASE + ONION_RETURN_2)
const ONION_SEND_2 = (NONCE_SIZE + ONION_SEND_BASE*2 + ONION_RETURN_1)
const ONION_SEND_1 = (NONCE_SIZE + ONION_SEND_BASE*3)

const ONION_MAX_DATA_SIZE = (ONION_MAX_PACKET_SIZE - (ONION_SEND_1 + 1))
const ONION_RESPONSE_MAX_DATA_SIZE = (ONION_MAX_PACKET_SIZE - (1 + ONION_RETURN_3))

const ONION_PATH_LENGTH = 3

type OnionPath struct {
	shrkey1 *CryptoKey
	shrkey2 *CryptoKey
	shrkey3 *CryptoKey

	pubkey1 *CryptoKey
	pubkey2 *CryptoKey
	pubkey3 *CryptoKey

	addr1   net.Addr
	nodepk1 *CryptoKey

	addr2   net.Addr
	nodepk2 *CryptoKey

	addr3   net.Addr
	nodepk3 *CryptoKey

	pathnum uint32
}

func (this *DHT) NewOnion() *Onion {
	that := &Onion{}
	that.dhto = this
	that.neto = this.Neto
	that.timestamp = time.Now()
	_, that.secsymkey, _ = NewCBKeyPair()

	neto := this.Neto
	neto.RegisterHandle(NET_PACKET_ONION_SEND_INITIAL, that.handle_send_initial, that)
	neto.RegisterHandle(NET_PACKET_ONION_SEND_1, that.handle_send_1, that)
	neto.RegisterHandle(NET_PACKET_ONION_SEND_2, that.handle_send_2, that)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_1, that.handle_recv_1, that)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_2, that.handle_recv_2, that)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_3, that.handle_recv_3, that)
	return that
}

func (this *Onion) Kill() {
	neto := this.neto
	neto.RegisterHandle(NET_PACKET_ONION_SEND_INITIAL, nil, nil)
	neto.RegisterHandle(NET_PACKET_ONION_SEND_1, nil, nil)
	neto.RegisterHandle(NET_PACKET_ONION_SEND_2, nil, nil)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_1, nil, nil)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_2, nil, nil)
	neto.RegisterHandle(NET_PACKET_ONION_RECV_3, nil, nil)
	this = nil
}

func (this *Onion) handle_send_initial(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}
func (this *Onion) handle_send_1(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}
func (this *Onion) handle_send_2(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}
func (this *Onion) handle_recv_1(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}
func (this *Onion) handle_recv_2(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}
func (this *Onion) handle_recv_3(object interface{}, addr net.Addr, data []byte, cbdata interface{}) (int, error) {
	return 0, nil
}

/* Create a new onion path.
 *
 * Create a new onion path out of nodes (nodes is a list of ONION_PATH_LENGTH nodes)
 *
 * new_path must be an empty memory location of atleast Onion_Path size.
 *
 * return -1 on failure.
 * return 0 on success.
 */
// int create_onion_path(const DHT *dht, Onion_Path *new_path, const Node_format *nodes);
func (this *DHT) NewOnionPath(nodes []*NodeFormat) *OnionPath {
	op := &OnionPath{}

	op.shrkey1, _ = CBBeforeNm(nodes[0].Pubkey, this.SelfSeckey)
	op.pubkey1 = this.SelfPubkey

	randpk, randsk, _ := NewCBKeyPair()
	op.shrkey2, _ = CBBeforeNm(nodes[1].Pubkey, randsk)
	op.pubkey2 = randpk

	randpk, randsk, _ = NewCBKeyPair()
	op.shrkey3, _ = CBBeforeNm(nodes[2].Pubkey, randsk)
	op.pubkey3 = randpk

	op.addr1 = nodes[0].Addr
	op.addr2 = nodes[1].Addr
	op.addr3 = nodes[2].Addr

	op.nodepk1 = nodes[0].Pubkey
	op.nodepk2 = nodes[1].Pubkey
	op.nodepk3 = nodes[2].Pubkey

	return op
}

/* Dump nodes in onion path to nodes of length num_nodes;
 *
 * return -1 on failure.
 * return 0 on success.
 */
// int onion_path_to_nodes(Node_format *nodes, unsigned int num_nodes, const Onion_Path *path);
func (this *OnionPath) ToNodes() (nodes []*NodeFormat) {
	n := &NodeFormat{}
	n.Addr = this.addr1
	n.Pubkey = this.pubkey1
	nodes = append(nodes, n)

	n = &NodeFormat{}
	n.Addr = this.addr2
	n.Pubkey = this.pubkey2
	nodes = append(nodes, n)

	n = &NodeFormat{}
	n.Addr = this.addr3
	n.Pubkey = this.pubkey3
	nodes = append(nodes, n)

	return
}

/* Create a onion packet.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
// int create_onion_packet(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, IP_Port dest,
//                        const uint8_t *data, uint16_t length);
func (this *OnionPath) CreatePacket(dest net.Addr, data []byte) (packet []byte, err error) {
	return
}

/* Create a onion packet to be sent over tcp.
 *
 * Use Onion_Path path to create packet for data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 * packet should be at least ONION_MAX_PACKET_SIZE big.
 *
 * return -1 on failure.
 * return length of created packet on success.
 */
// int create_onion_packet_tcp(uint8_t *packet, uint16_t max_packet_length, const Onion_Path *path, IP_Port dest,
//                            const uint8_t *data, uint16_t length);
func (this *OnionPath) CreatePacketTCP(dest net.Addr, data []byte) (packet []byte, err error) {
	return
}

/* Create and send a onion packet.
 *
 * Use Onion_Path path to send data of length to dest.
 * Maximum length of data is ONION_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
// int send_onion_packet(Networking_Core *net, const Onion_Path *path, IP_Port dest, const uint8_t *data, uint16_t length);
func (this *Onion) SendPacket(path *OnionPath, dest net.Addr, data []byte) error {
	return nil
}

/* Create and send a onion response sent initially to dest with.
 * Maximum length of data is ONION_RESPONSE_MAX_DATA_SIZE.
 *
 * return -1 on failure.
 * return 0 on success.
 */
// int send_onion_response(Networking_Core *net, IP_Port dest, const uint8_t *data, uint16_t length, const uint8_t *ret);
func (this *Onion) SendResponse(dest net.Addr, data []byte) (ret []byte, err error) {
	return
}

/* Function to handle/send received decrypted versions of the packet sent with send_onion_packet.
 *
 * return 0 on success.
 * return 1 on failure.
 *
 * Used to handle these packets that are received in a non traditional way (by TCP for example).
 *
 * Source family must be set to something else than AF_INET6 or AF_INET so that the callback gets called
 * when the response is received.
 */
// int onion_send_1(const Onion *onion, const uint8_t *plain, uint16_t len, IP_Port source, const uint8_t *nonce);
func (this *Onion) Send1(plain []byte, source net.Addr, nonce *CBNonce) error {
	return nil
}

/* Set the callback to be called when the dest ip_port doesn't have AF_INET6 or AF_INET as the family.
 *
 * Format: function(void *object, IP_Port dest, uint8_t *data, uint16_t length)
 */
// void set_callback_handle_recv_1(Onion *onion, int (*function)(void *, IP_Port, const uint8_t *, uint16_t),
// 	void *object);
func (this *Onion) SetCallbackHandleRecv1(f func(Object, net.Addr, []byte) int) {

}

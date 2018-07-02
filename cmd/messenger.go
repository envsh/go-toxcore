package main

const MAX_NAME_LENGTH = 128

/* TODO(irungentoo): this must depend on other variable. */
const MAX_STATUSMESSAGE_LENGTH = 1007

/* Used for TCP relays in Messenger struct (may need to be % 2 == 0)*/
const NUM_SAVED_TCP_RELAYS = 8

/* This cannot be bigger than 256 */
const MAX_CONCURRENT_FILE_PIPES = 256

// const FRIEND_ADDRESS_SIZE = (CRYPTO_PUBLIC_KEY_SIZE + sizeof(uint32_t) + sizeof(uint16_t))

const (
	MESSAGE_NORMAL = 0
	MESSAGE_ACTION = 1
)

/* NOTE: Packet ids below 24 must never be used. */
const PACKET_ID_ONLINE = 24
const PACKET_ID_OFFLINE = 25
const PACKET_ID_NICKNAME = 48
const PACKET_ID_STATUSMESSAGE = 49
const PACKET_ID_USERSTATUS = 50
const PACKET_ID_TYPING = 51
const PACKET_ID_MESSAGE = 64
const PACKET_ID_ACTION = (PACKET_ID_MESSAGE + MESSAGE_ACTION) /* 65 */
const PACKET_ID_MSI = 69
const PACKET_ID_FILE_SENDREQUEST = 80
const PACKET_ID_FILE_CONTROL = 81
const PACKET_ID_FILE_DATA = 82
const PACKET_ID_INVITE_CONFERENCE = 96
const PACKET_ID_ONLINE_PACKET = 97
const PACKET_ID_DIRECT_CONFERENCE = 98
const PACKET_ID_MESSAGE_CONFERENCE = 99
const PACKET_ID_LOSSY_CONFERENCE = 199

/* All packets starting with a byte in this range can be used for anything. */
const PACKET_ID_LOSSLESS_RANGE_START = 160
const PACKET_ID_LOSSLESS_RANGE_SIZE = 32
const PACKET_LOSSY_AV_RESERVED = 8 /* Number of lossy packet types at start of range reserved for A/V. */

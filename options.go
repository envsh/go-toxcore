package tox

/*
#include <stdlib.h>
#include <string.h>
#include <tox/tox.h>

extern void toxCallbackLog(Tox*, TOX_LOG_LEVEL, char*, uint32_t, char*, char*);

*/
import "C"
import "unsafe"

const (
	SAVEDATA_TYPE_NONE       = int(C.TOX_SAVEDATA_TYPE_NONE)
	SAVEDATA_TYPE_TOX_SAVE   = int(C.TOX_SAVEDATA_TYPE_TOX_SAVE)
	SAVEDATA_TYPE_SECRET_KEY = int(C.TOX_SAVEDATA_TYPE_SECRET_KEY)
)

const (
	PROXY_TYPE_NONE   = int(C.TOX_PROXY_TYPE_NONE)
	PROXY_TYPE_HTTP   = int(C.TOX_PROXY_TYPE_HTTP)
	PROXY_TYPE_SOCKS5 = int(C.TOX_PROXY_TYPE_SOCKS5)
)

const (
	LOG_LEVEL_TRACE   = int(C.TOX_LOG_LEVEL_TRACE)
	LOG_LEVEL_DEBUG   = int(C.TOX_LOG_LEVEL_DEBUG)
	LOG_LEVEL_INFO    = int(C.TOX_LOG_LEVEL_INFO)
	LOG_LEVEL_WARNING = int(C.TOX_LOG_LEVEL_WARNING)
	LOG_LEVEL_ERROR   = int(C.TOX_LOG_LEVEL_ERROR)
)

type ToxOptions struct {
	Ipv6_enabled            bool
	Udp_enabled             bool
	Proxy_type              int32
	Proxy_host              string
	Proxy_port              uint16
	Savedata_type           int
	Savedata_data           []byte
	Tcp_port                uint16
	Local_discovery_enabled bool
	Start_port              uint16
	End_port                uint16
	Hole_punching_enabled   bool
	ThreadSafe              bool
	LogCallback             func(_ *Tox, level int, file string, line uint32, fname string, msg string)
}

func NewToxOptions() *ToxOptions {
	toxopts := new(C.struct_Tox_Options)
	C.tox_options_default(toxopts)

	opts := new(ToxOptions)
	opts.Ipv6_enabled = bool(toxopts.ipv6_enabled)
	opts.Udp_enabled = bool(toxopts.udp_enabled)
	opts.Proxy_type = int32(toxopts.proxy_type)
	opts.Proxy_port = uint16(toxopts.proxy_port)
	opts.Tcp_port = uint16(toxopts.tcp_port)
	opts.Local_discovery_enabled = bool(toxopts.local_discovery_enabled)
	opts.Start_port = uint16(toxopts.start_port)
	opts.End_port = uint16(toxopts.end_port)
	opts.Hole_punching_enabled = bool(toxopts.hole_punching_enabled)

	return opts
}

func (this *ToxOptions) toCToxOptions() *C.struct_Tox_Options {
	toxopts := new(C.struct_Tox_Options)
	C.tox_options_default(toxopts)
	toxopts.ipv6_enabled = (C._Bool)(this.Ipv6_enabled)
	toxopts.udp_enabled = (C._Bool)(this.Udp_enabled)

	if this.Savedata_data != nil {
		toxopts.savedata_data = (*C.uint8_t)(C.malloc(C.size_t(len(this.Savedata_data))))
		C.memcpy(unsafe.Pointer(toxopts.savedata_data),
			unsafe.Pointer(&this.Savedata_data[0]), C.size_t(len(this.Savedata_data)))
		toxopts.savedata_length = C.size_t(len(this.Savedata_data))
		toxopts.savedata_type = C.TOX_SAVEDATA_TYPE(this.Savedata_type)
	}
	toxopts.tcp_port = (C.uint16_t)(this.Tcp_port)

	toxopts.proxy_type = C.TOX_PROXY_TYPE(this.Proxy_type)
	toxopts.proxy_port = C.uint16_t(this.Proxy_port)
	if len(this.Proxy_host) > 0 {
		toxopts.proxy_host = C.CString(this.Proxy_host)
	}

	toxopts.local_discovery_enabled = C._Bool(this.Local_discovery_enabled)
	toxopts.start_port = C.uint16_t(this.Start_port)
	toxopts.end_port = C.uint16_t(this.End_port)
	toxopts.hole_punching_enabled = C._Bool(this.Hole_punching_enabled)

	toxopts.log_callback = (*C.tox_log_cb)((unsafe.Pointer)(C.toxCallbackLog))

	return toxopts
}

//export toxCallbackLog
func toxCallbackLog(ctox *C.Tox, level C.TOX_LOG_LEVEL, file *C.char, line C.uint32_t, fname *C.char, msg *C.char) {
	t := cbUserDatas.get(ctox)
	if t != nil && t.opts != nil && t.opts.LogCallback != nil {
		t.opts.LogCallback(t, int(level), C.GoString(file), uint32(line), C.GoString(fname), C.GoString(msg))
	}
}

type BootNode struct {
	Addr   string
	Port   int
	Pubkey string
}

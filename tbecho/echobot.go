package tbecho


import (
	"fmt"
	// "io/ioutil"
	// "log"
	// "os"
	"math/rand"
	"strconv"
	"strings"
	// "time"

	// "github.com/envsh/go-toxcore-c"
	"github.com/envsh/toxera/tbcom"
	"github.com/TokTok/go-toxcore-c"
	// "github.com/kitech/gopp"
	// "github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"

	// _ "github.com/envsh/fedind/httpfs"
	// "github.com/envsh/fedind/httpfs"
	// "github.com/envsh/fedind/envcfg"
)


///

var debug = false

type EchoBot struct {

}

func init() {
	tbcom.Regit(NewEchoBot)
}

func NewEchoBot() *EchoBot {
	b := &EchoBot{}


	return b
}

func (b *EchoBot) OnSelfConnectionStatus(t *tox.Tox, status int, userData any) {
	if debug {
		log.Println("on self conn status:", status, userData)
	}
	log.Println("hehehhee", status)
}

func (b *EchoBot) OnFriendRequest(t *tox.Tox, friendId string, message string, userData any) {
	log.Println(friendId, message)
	num, err := t.FriendAddNorequest(friendId)
	if debug {
		log.Println("on friend request:", num, err)
	}
	if num < 100000 {
	// 	t.WriteSavedata(fname)
	// 	remputname := envcfg.Mynode + "_toxecho.data"
	// 	// err = httpfs.GhputFile(remputname, fname)
	// 	err = toxecho_remput_safe(remputname)
	// 	gopp.ErrPrint(err, remputname)
	}
}

func (b *EchoBot) OnFriendMessage(t *tox.Tox, friendNumber uint32, message string, userData any) {
	if debug {
		log.Println("on friend message:", friendNumber, message)
	}
	n, err := t.FriendSendMessage(friendNumber, "Re: "+message)
	if err != nil {
		log.Println(n, err)
	}
}

func (b *EchoBot) OnFriendConnectionStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
	if debug {
		friendId, err := t.FriendGetPublicKey(friendNumber)
		log.Println("on friend connection status:", friendNumber, status, friendId, err)
	}
}

func (b *EchoBot) OnFriendStatus(t *tox.Tox, friendNumber uint32, status int, userData any) {
		if debug {
			friendId, err := t.FriendGetPublicKey(friendNumber)
			log.Println("on friend status:", friendNumber, status, friendId, err)
		}
}

func (b *EchoBot) OnFriendStatusMessage(t *tox.Tox, friendNumber uint32, statusText string, userData any) {
	if debug {
		friendId, err := t.FriendGetPublicKey(friendNumber)
		log.Println("on friend status text:", friendNumber, statusText, friendId, err)
	}
}

///////// file/image
// when recv file request, not recv to local
// direct send file request.
// then recv one chunk, send one chunk

// some vars for file echo
var recvFiles = make(map[uint64]uint32, 0)
var sendFiles = make(map[uint64]uint32, 0)
var sendDatas = make(map[string][]byte, 0)
var chunkReqs = make([]string, 0)

func (b *EchoBot) OnFileRecvControl(t *tox.Tox, friendNumber uint32, fileNumber uint32,
	control int, userData any) {
	if debug {
		friendId, err := t.FriendGetPublicKey(friendNumber)
		log.Println("on recv file control:", friendNumber, fileNumber, control, friendId, err)
	}
	key := uint64(uint64(friendNumber)<<32 | uint64(fileNumber))
	if control == tox.FILE_CONTROL_RESUME {
		if fno, ok := sendFiles[key]; ok {
			t.FileControl(friendNumber, fno, tox.FILE_CONTROL_RESUME)
		}
	} else if control == tox.FILE_CONTROL_PAUSE {
		if fno, ok := sendFiles[key]; ok {
			t.FileControl(friendNumber, fno, tox.FILE_CONTROL_PAUSE)
		}
	} else if control == tox.FILE_CONTROL_CANCEL {
		if fno, ok := sendFiles[key]; ok {
			t.FileControl(friendNumber, fno, tox.FILE_CONTROL_CANCEL)
		}
	}
}

func (b *EchoBot) OnFileRecv(t *tox.Tox, friendNumber uint32, fileNumber uint32, kind uint32,
	fileSize uint64, fileName string, userData any) {
	if debug {
		friendId, err := t.FriendGetPublicKey(friendNumber)
		log.Println("on recv file:", friendNumber, fileNumber, kind, fileSize, fileName, friendId, err)
	}
	if fileSize > 1024*1024*1024 {
		// good guy
	}

	var reFileName = "Re_" + fileName
	reFileNumber, err := t.FileSend(friendNumber, kind, fileSize, reFileName, reFileName)
	if err != nil {
	}
	recvFiles[uint64(uint64(friendNumber)<<32|uint64(fileNumber))] = reFileNumber
	sendFiles[uint64(uint64(friendNumber)<<32|uint64(reFileNumber))] = fileNumber
}

func (b *EchoBot) OnFileRecvChunk(t *tox.Tox, friendNumber uint32, fileNumber uint32,
	position uint64, data []byte, userData any) {
	friendId, err := t.FriendGetPublicKey(friendNumber)
	if debug {
		// log.Println("on recv chunk:", friendNumber, fileNumber, position, len(data), friendId, err)
	}

	if len(data) == 0 {
		if debug {
			log.Println("recv file finished:", friendNumber, fileNumber, friendId, err)
		}
	} else {
		reFileNumber := recvFiles[uint64(uint64(fileNumber)<<32|uint64(fileNumber))]
		key := makekey(friendNumber, reFileNumber, position)
		sendDatas[key] = data
		trySendChunk := b.trySendChunk
		trySendChunk(t, friendNumber, reFileNumber, position)
	}
}

func (b *EchoBot) OnFileChunkRequest(t *tox.Tox, friendNumber uint32, fileNumber uint32, position uint64,
	length int, userData any) {
	friendId, err := t.FriendGetPublicKey(friendNumber)
	if length == 0 {
		if debug {
			log.Println("send file finished:", friendNumber, fileNumber, friendId, err)
		}
		origFileNumber := sendFiles[uint64(uint64(fileNumber)<<32|uint64(fileNumber))]
		delete(sendFiles, uint64(uint64(fileNumber)<<32|uint64(fileNumber)))
		delete(recvFiles, uint64(uint64(fileNumber)<<32|uint64(origFileNumber)))
	} else {
		key := makekey(friendNumber, fileNumber, position)
		chunkReqs = append(chunkReqs, key)
		trySendChunk := b.trySendChunk
		trySendChunk(t, friendNumber, fileNumber, position)
	}
}

func (b *EchoBot) trySendChunk(t *tox.Tox, friendNumber uint32, fileNumber uint32, position uint64) {
	sentKeys := make(map[string]bool, 0)
	for _, reqkey := range chunkReqs {
		lst := strings.Split(reqkey, "_")
		pos, err := strconv.ParseUint(lst[2], 10, 64)
		if err != nil {
		}
		if data, ok := sendDatas[reqkey]; ok {
			r, err := t.FileSendChunk(friendNumber, fileNumber, pos, data)
			if err != nil {
				if err.Error() == "toxcore error: 7" || err.Error() == "toxcore error: 8" {
				} else {
					log.Println("file send chunk error:", err, r, reqkey)
				}
				break
			} else {
				delete(sendDatas, reqkey)
				sentKeys[reqkey] = true
			}
		}
	}
	leftChunkReqs := make([]string, 0)
	for _, reqkey := range chunkReqs {
		if _, ok := sentKeys[reqkey]; !ok {
			leftChunkReqs = append(leftChunkReqs, reqkey)
		}
	}
	chunkReqs = leftChunkReqs
}

///// audio/video

func (b *EchoBot) OnCall(av *tox.ToxAV, friendNumber uint32, audioEnabled bool,
	videoEnabled bool, userData any) {
	if debug {
		log.Println("oncall:", friendNumber, audioEnabled, videoEnabled)
	}
	var audioBitRate uint32 = 48
	var videoBitRate uint32 = 64
	r, err := av.Answer(friendNumber, audioBitRate, videoBitRate)
	if err != nil {
		log.Println(err, r)
	}
}

func (b *EchoBot) OnCallState(av *tox.ToxAV, friendNumber uint32, state uint32, userData any) {
	if debug {
		log.Println("on call state:", friendNumber, state)
	}
}

func (b *EchoBot) OnAudioReceiveFrame(av *tox.ToxAV, friendNumber uint32, pcm []byte,
	sampleCount int, channels int, samplingRate int, userData any) {
	if debug {
		if rand.Int()%23 == 3 {
			log.Println("on recv audio frame:", friendNumber, len(pcm), sampleCount, channels, samplingRate)
		}
	}
	r, err := av.AudioSendFrame(friendNumber, pcm, sampleCount, channels, samplingRate)
	if err != nil {
		log.Println(err, r)
	}
}

func (b *EchoBot) OnVideoReceiveFrame(av *tox.ToxAV, friendNumber uint32, width uint16, height uint16,
	frames []byte, userData any) {
	if debug {
		if rand.Int()%45 == 3 {
			log.Println("on recv video frame:", friendNumber, width, height, len(frames))
		}
	}
	r, err := av.VideoSendFrame(friendNumber, width, height, frames)
	if err != nil {
		log.Println(err, r)
	}
}

// file forward map key
func makekey(no uint32, a0 any, a1 any) string {
	return fmt.Sprintf("%d_%v_%v", no, a0, a1)
}

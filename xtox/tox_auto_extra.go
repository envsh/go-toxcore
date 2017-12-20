package xtox

import (
	"fmt"
	"gopp"
	"log"
	"math"
	"strings"
	"sync"
	"time"

	tox "github.com/kitech/go-toxcore"
	// "github.com/kitech/go-toxcore/xtox"
	"github.com/kitech/godsts/sets/hashset"
	textdistance "github.com/masatana/go-textdistance"
	"github.com/xrash/smetrics"
)

/*
features:
[x] net connection help bot, some echobot. for connection stability
[x] auto accept group invite
[x] auto accept frined request
[ ] auto check friend delete me
[x] auto remove only me left invited group chat
[ ] auto join groupbot's group chat
[x] auto keep groupchat title
[ ] auto detect and show peer join/leave event
*/

const (
	FOTA_NONE                   = 0 << 0
	FOTA_ALL                    = int(math.MaxInt64)
	FOTA_ADD_NET_HELP_BOTS      = 1 << 0
	FOTA_ACCEPT_GROUP_INVITE    = 1 << 1
	FOTA_ACCEPT_FRIEND_REQUEST  = 1 << 2
	FOTA_REMOVE_ONLY_ME_INVITED = 1 << 3
	FOTA_REMOVE_ONLY_ME_ALL     = 1 << 4
	FOTA_JOIN_GROUPBOT_ROOMS    = 1 << 5
	FOTA_CHECK_FRIEND_DELETE_ME = 1 << 6
	FOTA_KEEP_GROUPCHAT_TITLE   = 1 << 7
	FOTA_SHOW_PEER_JOIN_LEAVE   = 1 << 8
)

type toxabContext struct {
	feats int
	inst  *tox.Tox
}

var toxabCtxs = sync.Map{} // *tox.Tox => *toxabContext

func SetAutoBotFeatures(t *tox.Tox, f int) {
	if _, loaded := toxabCtxs.LoadOrStore(t, &toxabContext{f, t}); loaded {
		return // already exists
	}

	t.CallbackSelfConnectionStatusAdd(func(this *tox.Tox, status int, userData interface{}) {
		if matchFeat(this, FOTA_ADD_NET_HELP_BOTS) {
			autoAddNetHelperBots(this, status, userData)
		}
	}, nil)

	t.CallbackFriendRequestAdd(func(this *tox.Tox, pubkey string, message string, userData interface{}) {
		if matchFeat(this, FOTA_ACCEPT_FRIEND_REQUEST) {
			_, err := t.FriendAddNorequest(pubkey)
			gopp.ErrPrint(err, pubkey, message)
		}
	}, nil)

	t.CallbackConferenceInviteAdd(func(this *tox.Tox, friendNumber uint32, itype uint8, cookie string, userData interface{}) {
		if matchFeat(this, FOTA_ACCEPT_GROUP_INVITE) {
			var err error
			var groupNumber uint32
			switch int(itype) {
			case tox.CONFERENCE_TYPE_TEXT:
				groupNumber, err = t.ConferenceJoin(friendNumber, cookie)
			case tox.CONFERENCE_TYPE_AV:
				var groupNumber_ int
				groupNumber_, err = t.JoinAVGroupChat(friendNumber, cookie)
				groupNumber = uint32(groupNumber_)
			}
			gopp.ErrPrint(err, friendNumber, itype, cookie)
			if err != nil {
				toxaa.onGroupInvited(int(groupNumber))
			}
		}
	}, nil)

	t.CallbackConferenceTitleAdd(func(this *tox.Tox, groupNumber uint32, peerNumber uint32, title string, userData interface{}) {
		if matchFeat(this, FOTA_KEEP_GROUPCHAT_TITLE) {
			tryKeepGroupTitle(t, groupNumber, peerNumber, title)
		}
	}, nil)

	t.CallbackConferenceNameListChangeAdd(func(this *tox.Tox, groupNumber uint32, peerNumber uint32, change uint8, userData interface{}) {
		ok := checkOnlyMeLeftGroupClean(t, int(groupNumber), int(peerNumber), change)
		if ok && matchFeat(this, FOTA_REMOVE_ONLY_ME_ALL) {
			// real delete it
			_, err := t.ConferenceDelete(groupNumber)
			gopp.ErrPrint(err)
		} else if ok && matchFeat(this, FOTA_REMOVE_ONLY_ME_INVITED) {
			if IsInvitedGroup(this, groupNumber) {
				// real delete it
				removedInvitedGroupClean(this, int(groupNumber))
			}
		}
	}, nil)
}

// feat匹配测试函数
func matchFeat(this *tox.Tox, f int) bool {
	if toxabCtxx, loaded := toxabCtxs.Load(this); loaded {
		toxabCtx := toxabCtxx.(*toxabContext)
		if toxabCtx.feats&f != 0 {
			return true
		}
	}
	return false
}

////////////////////////////////
var groupbot = "56A1ADE4B65B86BCD51CC73E2CD4E542179F47959FE3E0E21B4B0ACDADE51855D34D34D37CB5"

// 帮助改进p2p网络稳定的bot列表
var nethlpbots = []string{
	groupbot, //groupbot@toxme.io
	"76518406F6A9F2217E8DC487CC783C25CC16A15EB36FF32E335A235342C48A39218F515C39A6", //echobot@toxme.io
	"7F3948BDF42F2DA68468ADA46783B392EF8ADD60E8BDE3CD04981766B5A7883747824B7108D7", //toxme@toxme.io
	"DD7A68B345E0AA918F3544AA916B5CA6AED6DE80389BFF1EF7342DACD597943D62BDEED1FC67", // my echobot
	//, // kalinaBot@toxme.io,
	//, // LainBot@toxme.io,
}

// TODO sync锁
// tox 实例的一些自动化行为整理
type toxAutoAction struct {
	delGroupC chan int // 用于删除被邀群的channel，被主tox循环使用

	theirGroups map[int]bool // accepted group number => true

	initGroupNames sync.Map // uint32=>string group number => group title
}

func newToxAutoAction() *toxAutoAction {
	this := &toxAutoAction{}
	this.delGroupC = make(chan int, 16)

	this.theirGroups = make(map[int]bool)

	return this
}

var toxaa = newToxAutoAction()

func (this *toxAutoAction) initGroupNamesLen() int {
	length := 0
	this.initGroupNames.Range(func(key interface{}, value interface{}) bool {
		length++
		return true
	})
	return length
}

// 需要与 tox iterate并列执行的函数
// 比如执行删除群的操作。这个操作如果在iterate中执行，会导致程序崩溃。
func (this *toxAutoAction) iterateTasks() {

}

// TODO accept多次会出现什么情况
// called in onGroupInvite, when accepted
func (this *toxAutoAction) onGroupInvited(groupNumber int) {
	this.theirGroups[groupNumber] = true
}

// for self connection status callback
// 在本bot上线时，自动添加几个常期在线bot，能够让本bot的网络稳定些
func autoAddNetHelperBots(t *tox.Tox, status int, d interface{}) {
	log.Println(status, tox.ConnStatusString(status))
	for _, bot := range nethlpbots {
		friendNumber, err := t.FriendByPublicKey(bot)
		if err == nil && status > tox.CONNECTION_NONE {
			if bot == groupbot {
				// t.FriendDelete(friendNumber)
				// err = errors.New("hehe")
			}
		}

		// 查找不到该好友信息，并且当前状态是连接状态
		if err != nil && status > tox.CONNECTION_NONE {
			ret, err := t.FriendAdd(bot, fmt.Sprintf("Hey %d, me here", friendNumber))
			if err != nil {
				log.Println(ret, err)
			}
		}
	}
}

/*
实现自动摘除被别人邀请，但当前只有自己在了的群组。
*/
func autoRemoveInvitedGroups(t *tox.Tox,
	groupNumber int, peerNumber int, change uint8, ud interface{}) {
	// this := toxaa

	// check only me left case
	checkOnlyMeLeftGroup(t, groupNumber, peerNumber, change)
}

// 被邀请的群组被删除的处理
// 清缓存映射
// 尝试重新加入，因为有可能是我方掉线了。
func removedInvitedGroup(t *tox.Tox, groupNumber int) error {
	groupTitle, err := t.ConferenceGetTitle(uint32(groupNumber))
	gopp.ErrPrint(err)
	if IsInvitedGroup(t, uint32(groupNumber)) {
		log.Println("Delete invited group: ", groupNumber, groupTitle)
		delete(toxaa.theirGroups, groupNumber)
		toxaa.initGroupNames.Delete(uint32(groupNumber))
		_, err = t.ConferenceDelete(uint32(groupNumber))
		gopp.ErrPrint(err)

		// try rejoin
		tryJoinOfficalGroupbotManagedGroups(t)
	} else {
		log.Println("Self created group: don't delete:", groupNumber, groupTitle)
		// 可能也是要删除的，不过删除之后要做其他的工作
	}
	return nil
}

func removedInvitedGroupClean(t *tox.Tox, groupNumber int) error {
	groupTitle, err := t.ConferenceGetTitle(uint32(groupNumber))
	gopp.ErrPrint(err)
	if IsInvitedGroup(t, uint32(groupNumber)) {
		log.Println("Delete invited group: ", groupNumber, groupTitle)
		delete(toxaa.theirGroups, groupNumber)
		toxaa.initGroupNames.Delete(uint32(groupNumber))
		_, err = t.ConferenceDelete(uint32(groupNumber))
		gopp.ErrPrint(err)
	} else {
		log.Println("Self created group: don't delete:", groupNumber, groupTitle)
		// 可能也是要删除的，不过删除之后要做其他的工作
	}
	return nil
}

// 检查群组中是否只有自己了，来自 callback name list change
// 但是只需要关注 PEER_DEL事件
func checkOnlyMeLeftGroup(t *tox.Tox, groupNumber int, peerNumber int, change uint8) {
	this := toxaa

	if !checkOnlyMeLeftGroupClean(t, groupNumber, peerNumber, change) {
		return
	}

	groupTitle, err := t.GroupGetTitle(groupNumber)
	if err != nil {
		log.Println("wtf", err, groupNumber, peerNumber, change)
	}
	peerName, err := t.GroupPeerName(groupNumber, peerNumber)
	if err != nil {
		if change != tox.CHAT_CHANGE_PEER_DEL {
			log.Println("wtf", err, peerName)
		}
	}
	// var peerPubkey string

	// check our create group or not
	// 即使不是自己创建的群组，在只剩下自己之后，也可以不删除。因为这个群的所有人就是自己了。
	// 这里找一下为什么程序会崩溃吧
	if _, ok := this.theirGroups[groupNumber]; ok {
		log.Println("invited group matched, clean it", groupNumber, groupTitle)
		delete(this.theirGroups, groupNumber)
		grptype, err := t.GroupGetType(uint32(groupNumber))
		log.Println("before delete group chat", groupNumber, grptype, err)
		switch uint8(grptype) {
		case tox.GROUPCHAT_TYPE_AV:
			// log.Println("dont delete av groupchat for a try", groupNumber, ok, err)
		case tox.GROUPCHAT_TYPE_TEXT:
			// ok, err := this._tox.DelGroupChat(groupNumber)
			// log.Println("after delete group chat", groupNumber, ok, err)
		default:
			log.Fatal("wtf")
		}
		time.AfterFunc(1*time.Second, func() {
			this.delGroupC <- groupNumber
			// why not delete here? deadlock? crash?
		})
		log.Println("Rename....", groupTitle, makeDeletedGroupName(groupTitle))
		t.GroupSetTitle(groupNumber, makeDeletedGroupName(groupTitle))
		log.Println("dont delete invited groupchat for a try", groupNumber, ok, err)
	}
}

// 干净版本的check，只做check，不做删除
func checkOnlyMeLeftGroupClean(t *tox.Tox, groupNumber int, peerNumber int, change uint8) bool {
	if change != tox.CHAT_CHANGE_PEER_DEL {
		return false
	}

	groupTitle, err := t.GroupGetTitle(groupNumber)
	if err != nil {
		log.Println("wtf", err, groupNumber, peerNumber, change)
	}
	peerName, err := t.GroupPeerName(groupNumber, peerNumber)
	if err != nil {
		if change != tox.CHAT_CHANGE_PEER_DEL {
			log.Println("wtf", err, peerName)
		}
	}
	// var peerPubkey string

	// check only me left case
	if pn := t.GroupNumberPeers(groupNumber); pn == 1 {
		log.Println("oh, only me left:", groupNumber, groupTitle, IsInvitedGroup(t, uint32(groupNumber)))
		return true
	}

	return false
}

// 无用群改名相关功能
func makeDeletedGroupName(groupTitle string) string {
	return fmt.Sprintf("#deleted_invited_groupchat_%s_%s",
		time.Now().Format("20060102_150405"), groupTitle)
}

func isDeletedGroupName(groupTitle string) bool {
	return strings.HasPrefix(groupTitle, "#deleted_invited_groupchat_")
}

func getDeletedGroupName(groupTitle string) string {
	s := groupTitle[len(makeDeletedGroupName("")):]
	return s
}

func isGroupbot(pubkey string) bool { return strings.HasPrefix(groupbot, pubkey) }

// raw group name map
var fixedGroups = map[string]string{
	// "tox-en": "invite 0",
	// "Official Tox groupchat": "invite 0",
	"Tox Public Chat": "invite 0",
	"Chinese 中文":      "invite 1",
	// "tox-cn": "invite 1",
	// "tox-ru": "invite 3",
	// "Club Cyberia": "invite 3",
	// "Club Cyberia: No Pedos, No Pervs": "invite 3",
	// "Club Cyberia: Linux General: No Pedos": "invite 4",
	"Russian Tox Chat (kalina@toxme.io)": "invite 3",
	// "test autobot":                     "invite 4",
	// "Russian Tox Chat (Use kalina@toxme.io or 12EDB939AA529641CE53830B518D6EB30241868EE0E5023C46A372363CAEC91C2C948AEFE4EB": "invite 5",
}

var skipTitleChangeWhiteList *hashset.Set = hashset.New()

func init() {
	skipTitleChangeWhiteList.Add(
		"415732B8A549B2A1F9A278B91C649B9E30F07330E8818246375D19E52F927C57",
		"398C8161D038FD328A573FFAA0F5FAAF7FFDE5E8B4350E7D15E6AFD0B993FC52")
}

// 检测是否是固定群组
func isOfficialGroupbotManagedGroups(name string) (rname string, ok bool) {
	for n, _ := range fixedGroups {
		if name == n {
			return n, true
		}
	}

	// 再次尝试采用相似度计算法
	for n, _ := range fixedGroups {
		if false {
			dis := textdistance.JaroWinklerDistance(n, name)
			_ = dis
		}

		dis := smetrics.JaroWinkler(n, name, 0.75, 5)
		if dis > 0.750 {
			log.Println(n, name, dis, dis > 0.750)
			return n, true
		}
	}

	// 再次尝试采用前缀对比法
	for n, _ := range fixedGroups {
		if len(name) > 5 && strings.HasPrefix(n, name) {
			return n, true
		}
	}
	return
}

// 检查自己是否在固定群中，如果不在，则尝试发送groupbot进群消息
// friend connection callback
// self connection callback
// timer callback
func tryJoinOfficalGroupbotManagedGroups(t *tox.Tox) {
	friendNumber, err := t.FriendByPublicKey(groupbot)
	gopp.ErrPrint(err)
	status, err := t.FriendGetConnectionStatus(friendNumber)
	if status == tox.CONNECTION_NONE {
		return
	}

	curGroups := make(map[string]int32)
	for _, gn := range t.GetChatList() {
		gt, _ := t.GroupGetTitle(int(gn))
		curGroups[gt] = gn
	}

	// 查找群是否是当前的某个群，相似比较
	incurrent := func(name string) bool {
		for groupTitle, gn := range curGroups {
			isInvited := IsInvitedGroup(t, uint32(gn))
			if !isInvited { // 被邀请的群组才有查找意义
				continue
			}

			if groupTitle == name {
				return true
			}

			if false {
				dis := textdistance.JaroWinklerDistance(groupTitle, name)
				_ = dis
			}
			dis := smetrics.JaroWinkler(groupTitle, name, 0.75, 5)
			if dis > 0.750 {
				log.Println(groupTitle, name, dis, dis > 0.750)
				return true
			}

			if strings.HasPrefix(groupTitle, name) {
				return true
			}
		}
		return false
	}

	// 不在这群，或者在这群，但只自己在了
	// TODO 在发送前，通过info得到现有的群组列表。如果不存在这个群组，则不要发送invite了
	for name, handler := range fixedGroups {
		if !incurrent(name) {
			log.Println("Try join:", name, handler)
			n, err := t.FriendSendMessage(friendNumber, handler)
			gopp.ErrPrint(err, n, friendNumber, name, handler)
		}
	}
}

// 保持群组名称，防止其他用户修改标题，来自CallbackConferenceTitle
func tryKeepGroupTitle(t *tox.Tox, groupNumber uint32, peerNumber uint32, title string) {
	// 在这调用这个函数不安全，有时成功，有时失败
	peerPubkey, err := t.ConferencePeerGetPublicKey(groupNumber, peerNumber)
	_ = err

	// 防止其他用户修改标题
	// TODO 有些群组标题不能我们来管理，不能自动保持。+1
	ovalue, ok := toxaa.initGroupNames.Load(groupNumber)
	if ok {
		if ovalue.(string) != title {
			// 无法取到peerPubkey时，恢复title
			// 或者取了peerPubkey，但不是自己时恢复title
			// 就是说，如果取到了peerPubkey并且是自己，是可以设置新title的
			if skipTitleChangeWhiteList.Contains(peerPubkey) {
				log.Println("Peer in title keep whitelist, skip.")
			} else if peerPubkey == "" || (peerPubkey != "" && peerPubkey != t.SelfGetPublicKey()) {
				log.Println("Restore title:", ovalue, title)
				// restore initilized group title
				// 设置新title必须放在cbtitle事件循环之外设置，否则会导致死循环
				time.AfterFunc(200*time.Millisecond, func() {
					t.ConferenceSetTitle(groupNumber, ovalue.(string))
				})
			}
		}
	} else {
		if title == "" || title == "None" {
			log.Println("Group name not set:", groupNumber, title, toxaa.initGroupNamesLen())
		} else {
			log.Println("Saving initGroupNames:", groupNumber, title, toxaa.initGroupNamesLen())
			toxaa.initGroupNames.Store(groupNumber, title)
		}
	}
}

// 尝试拉好友进固定群组
// 具体进哪些群，目前只提供进 # tox-cn 群组
// 后续如果有更强大的配置功能，可以让用户选择自动进哪些群
func tryPullFriendFixedGroups(t *tox.Tox, friendNumber uint32, status int) {

}

// groupbot's response message
func fixSpecialMessage(t *tox.Tox, friendNumber uint32, msg string) {
	pubkey, err := t.FriendGetPublicKey(friendNumber)
	if err != nil {
		log.Println(err)
	} else {
		if isGroupbot(pubkey) {
			if msg == "Group doesn't exist." {
				log.Println(msg, ", try create one.")
				t.FriendSendMessage(friendNumber, "group text")
			} else if msg == "Invalid password." {
				log.Println("Maybe wrong group:", msg)
			}
		}
	}
}

///

func toxmeLookup(name string) {

}

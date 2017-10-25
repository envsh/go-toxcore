package tox

func (this *Tox) AllConferencesTitles() map[uint32]string {
	ret := map[uint32]string{}
	cids := this.ConferenceGetChatlist()
	for _, cid := range cids {
		title, err := this.ConferenceGetTitle(cid)
		if err != nil {
			continue
		}
		ret[cid] = title
	}
	return ret
}

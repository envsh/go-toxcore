package tox

type callHookMethods struct {
	ConferenceJoin     func(friendNumber uint32, groupNumber uint32, data []byte)
	ConferenceDelete   func(groupNumber uint32)
	ConferenceNew      func(groupNumber uint32)
	ConferenceSetTitle func(groupNumber uint32, title string)
}

// include av group
func (this *Tox) HookConferenceJoin(fn func(friendNumber uint32, groupNumber uint32, data []byte)) {
	this.hooks.ConferenceJoin = fn
}

func (this *Tox) HookConferenceDelete(fn func(groupNumber uint32)) {
	this.hooks.ConferenceDelete = fn
}

func (this *Tox) HookConferenceNew(fn func(groupNumber uint32)) {
	this.hooks.ConferenceDelete = fn
}

func (this *Tox) HookConferenceSetTitle(fn func(groupNumber uint32, title string)) {
	this.hooks.ConferenceSetTitle = fn
}

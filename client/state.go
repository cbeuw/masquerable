package client

import (
	"crypto/sha256"
	"time"
)

type stateManager interface {
	ParseConfig(string) error
	SetAESKey(string)
}

// State stores global variables
type State struct {
	RemoteAddr     string
	Now            func() time.Time
	Opaque         int
	Key            string
	TicketTimeHint int
	AESKey         []byte
	ServerName     string
}

// SetAESKey calculates the SHA256 of the string key
func (sta *State) SetAESKey() {
	h := sha256.New()
	h.Write([]byte(sta.Key))
	sta.AESKey = h.Sum(nil)
}

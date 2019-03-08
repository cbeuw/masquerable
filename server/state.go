package server

import (
	"crypto/sha256"
	"time"
)

// State type stores the global state of the program
type State struct {
	RedirAddr  string
	Key        string
	AESKey     []byte
	Now        func() time.Time
	MurmurAddr string
	BindAddr   string
}

// SetAESKey calculates the SHA256 of the string key
func (sta *State) SetAESKey() {
	h := sha256.New()
	h.Write([]byte(sta.Key))
	sta.AESKey = h.Sum(nil)
}

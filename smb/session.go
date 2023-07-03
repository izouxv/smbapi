package smb

import (
	"log"
	"net"
)

type session struct {
	IsSigningRequired bool
	IsAuthenticated   bool
	debug             bool
	securityMode      uint16
	sessionID         uint64
	conn              net.Conn
	dialect           uint16
}

func (s *session) Debug(msg string, err error) {
	if s.debug {
		log.Println("[ DEBUG ] ", msg)
		if err != nil {
			// debug.PrintStack()
		}
	}
}

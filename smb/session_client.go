package smb

import (
	"errors"
	"fmt"
	"net"
	"sync/atomic"

	"github/izouxv/smbapi/gss"
	"github/izouxv/smbapi/ntlmssp"
)

//TODO tcp发过去的消息会乱序, 需要用msgid chan来处理单独的协议. 马上send马上recv的消息可能msgId对不上

type Options struct {
	Host        string
	Port        int
	Workstation string
	Domain      string
	User        string
	Password    string
}

func validateOptions(opt Options) error {
	if opt.Host == "" {
		return errors.New("Missing required option: Host")
	}
	if opt.Port < 1 || opt.Port > 65535 {
		return errors.New("Invalid or missing value: Port")
	}
	return nil
}

type SessionC struct {
	session

	//client level
	trees     map[string]uint32
	options   Options
	messageID uint64 //for client msgId
	Challenge ntlmssp.Challenge
}

func NewSessionClient(opt Options, debug bool) (s *SessionC, err error) {

	if err := validateOptions(opt); err != nil {
		return nil, err
	}

	conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", opt.Host, opt.Port))
	if err != nil {
		return
	}

	s = &SessionC{
		session: session{
			IsSigningRequired: false,
			IsAuthenticated:   false,
			debug:             debug,
			conn:              conn,
			securityMode:      0,
			sessionID:         0,
			dialect:           0,
			// trees:             make(map[string]uint32),
		},
		options: opt,
	}

	s.Debug("Negotiating protocol", nil)
	err = s.NegotiateProtocolClient()
	if err != nil {
		return
	}
	return s, nil
}

func (s *SessionC) NegotiateProtocolClient() error {
	s.Debug("Sending NegotiateProtocol request", nil)

	// myMechType := gss.KRB5SSPMechTypeOid
	myMechType := gss.NtLmSSPMechTypeOid

	if true {
		requestNego := s.NewNegotiateRequest()
		responseNego := &NegotiateResponse{
			SecurityBlob: &gss.NegTokenInit{},
		}
		if err := s.RPC(requestNego, responseNego); err != nil {
			return err
		}
		if err := requestNego.ClientAction(s, responseNego); err != nil {
			return err
		}
	}

	if true {
		s.Debug("Sending SessionSetup1 request", nil)
		setupRequest1 := s.NewSessionSetup1Request(myMechType)
		setupResponse1 := &SessionSetup1Response{
			SecurityBlob: &gss.NegTokenResp{},
		}
		if err := s.RPC(setupRequest1, setupResponse1); err != nil {
			return err
		}
		setupRequest1.ClientAction(s, setupResponse1)
	}

	if true {
		s.Debug("Sending SessionSetup2 request", nil)
		setupRequest2, err := s.NewSessionSetup2Request()
		if err != nil {
			return err
		}
		setupResponse2 := &SessionSetup2Response{
			SecurityBlob: &gss.NegTokenResp{},
		}
		if err = s.RPC(setupRequest2, setupResponse2); err != nil {
			return err
		}
		setupRequest2.ClientAction(s, setupResponse2)
	}

	return nil
}

func (s *SessionC) Close() {
	s.Debug("Closing session", nil)
	for k, _ := range s.trees {
		s.TreeDisconnect(k)
	}
	s.Debug("Closing TCP connection", nil)
	s.conn.Close()
	s.Debug("Session close completed", nil)
}

func (s *SessionC) newHeader(cmd Command) Header {
	msgId := atomic.AddUint64(&s.messageID, 1)
	return newHeader(cmd, msgId, s.sessionID)

	// return Header{
	// 	ProtocolID:   []byte(ProtocolSmb2),
	// 	HeaderLength: 64,
	// 	Command:      cmd,
	// 	MessageID:    msgId,
	// 	SessionID:    s.sessionID,
	// 	Signature:    make([]byte, 16),
	// 	CreditCharge: 1,
	// }
}

func newHeader(cmd Command, msgId, sessionId uint64) Header {
	return Header{
		ProtocolID:   []byte(ProtocolSmb2),
		HeaderLength: 64,
		Command:      cmd,
		MessageID:    msgId,
		SessionID:    sessionId, //  s.sessionID,
		Signature:    make([]byte, 16),
		CreditCharge: 1,
	}
}

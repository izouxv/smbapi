package smb

import (
	"bytes"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"sync/atomic"

	"github/izouxv/smbapi/gss"
	"github/izouxv/smbapi/ntlmssp"
	"github/izouxv/smbapi/smb/encoder"

	"github.com/izouxv/logx"
)

type SessionSetup2Request struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenResp
}

type SessionFlags uint16

const (
	SMB2_SESSION_FLAG_IS_GUEST SessionFlags = 0x0001
	SMB2_SESSION_FLAG_IS_NULL  SessionFlags = 0x0002
	// SMB2_SESSION_FLAG_ENCRYPT_DATA SessionFlags = 0x0004 //only valid for the SMB 3.x dialect family
)

var treeId = uint32(0)

type SessionSetup2Response struct {
	Header
	StructureSize        uint16
	SessionFlags         uint16 //SessionFlags
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

func (data *SessionSetup2Request) ServerAction(ctx *DataCtx) (interface{}, error) {

	resp2 := SessionSetup2Response{
		SecurityBlob:  &gss.NegTokenResp{},
		StructureSize: 9,
	}

	resp2.Header = data.Header
	resp2.Header.Credits = 1
	resp2.Header.Status = StatusLogonFailure
	resp2.Header.SessionID = ctx.session.sessionID
	// respSetUp2.StructureSize = 9
	resp2.Header.Flags = SMB2_FLAGS_RESPONSE
	// respSetUp2.SessionFlags = uint16(SMB2_SESSION_FLAG_IS_GUEST)
	// respSetUp2.SessionFlags = uint16(SMB2_SESSION_FLAG_IS_NULL)

	var ntlmsspnegAuth ntlmssp.Authenticate
	ResponseToken := data.SecurityBlob.ResponseToken
	if err := encoder.Unmarshal(ResponseToken, &ntlmsspnegAuth); err != nil {
		return ERR(data.Header, StatusLogonFailure)
	}

	// if true {
	// 	v := ntlmssp.Version{}
	// 	r := bytes.NewReader(ntlmsspnegAuth.Version)
	// 	err = binary.Read(r, binary.LittleEndian, &v)
	// 	if err != nil {
	// 		return &respSetUp2
	// 	}
	// }

	// logx.Printf("name: %v", ntlmsspnegAuth.UserName)
	// logx.Printf("domain name: %v", ntlmsspnegAuth.DomainName)
	// logx.Printf("domain name: %v", ntlmsspnegAuth.Workstation)

	loginSuc := false
	if name, err := encoder.FromUnicode(ntlmsspnegAuth.UserName); err == nil {
		logx.Printf("name: %v", name)
		if domain, err := encoder.FromUnicode(ntlmsspnegAuth.DomainName); err == nil {
			password, err := ctx.session.getPwd(name)
			if err != nil {
				return ERR(data.Header, StatusLogonFailure)
			}

			if true {
				//NT v2
				w := bytes.NewBuffer(make([]byte, 0))
				binary.Write(w, binary.LittleEndian, ctx.session.ServerChallenge)
				serverChallenge := w.Bytes()
				clientChallengeStructurePadded := ntlmsspnegAuth.NtChallengeResponse[16:]

				clientNTProof := ntlmsspnegAuth.NtChallengeResponse[:16]
				expectedNTProof := ntlmssp.NTLMv2Verify(serverChallenge, clientChallengeStructurePadded, password, name, domain)
				loginSuc = bytes.Equal(clientNTProof, expectedNTProof)

				if loginSuc {
					ctx.session.IsAuthenticated = true

					// // https://msdn.microsoft.com/en-us/library/cc236700.aspx
					// byte[] responseKeyNT = NTLMCryptography.NTOWFv2(password, message.UserName, message.DomainName);
					// byte[] ntProofStr = ByteReader.ReadBytes(message.NtChallengeResponse, 0, 16);
					// sessionBaseKey = new HMACMD5(responseKeyNT).ComputeHash(ntProofStr);
					// keyExchangeKey = sessionBaseKey;
					keyExchangeKey := ntlmssp.NTLMv2KeyExchangeKey(clientNTProof, password, name, domain)
					// if (ntlmsspnegAuth.NegotiateFlags & ntlmssp.FlgNegKeyExch) > 0 {
					// 	s.SessionKey = RC4.Decrypt(keyExchangeKey, message.EncryptedRandomSessionKey)
					// } else {
					ctx.session.SessionKey = keyExchangeKey
					// }

					tid := atomic.AddUint64(&ctx.session.fileNum, 1)
					// trees, err := conn.openUserCallback(nil)
					anchors, err := ctx.session.getTree(name)
					if err != nil {
						return &resp2, nil
					}

					logx.Printf("LOGIN SUC, IP: %v", ctx.conn.RemoteAddr().String())

					ctx.session.SetAnchor(tid, anchors)
				}
			}

		}
	}

	if !loginSuc {
		return ERR(data.Header, StatusLogonFailure)
	}

	if false {
		ServerChallenge := rand.Uint64()
		challenge := ntlmssp.NewChallenge(ServerChallenge)
		challenge.TargetName = []byte("testGoGo")
		challengeData, err := encoder.Marshal(&challenge)
		if err != nil {
			return ERR(data.Header, StatusLogonFailure)
		}
		resp2.SecurityBlob = &gss.NegTokenResp{
			ResponseToken: challengeData,
			SupportedMech: myMech(),
			NegResult:     asn1.Enumerated(gss.Accept_completed),
		}
	}
	resp2.SecurityBlob = &gss.NegTokenResp{
		NegResult: asn1.Enumerated(gss.Accept_completed),
	}

	resp2.Header.Status = StatusOk

	return &resp2, nil
}

func (requestSetUp2 *SessionSetup2Request) ClientAction(s *SessionC, negRes *SessionSetup2Response) error {

	if negRes.Status != StatusOk {
		status, _ := StatusMap[negRes.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.IsAuthenticated = true

	s.Debug("Completed NegotiateProtocol and SessionSetup", nil)

	return nil
}

func (s *SessionC) NewSessionSetup2Request() (*SessionSetup2Request, error) {

	// No hash, use password
	s.Debug("Performing password-based authentication", nil)
	auth := ntlmssp.NewAuthenticatePass(s.options.Domain, s.options.User, s.options.Workstation, s.options.Password, s.Challenge)

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		s.Debug("", err)
		return nil, err
	}

	if true {
		resp := &ntlmssp.Authenticate{}
		err := encoder.Unmarshal(responseToken, resp)
		if err != nil {
			s.Debug("", err)
		}

	}

	header := s.newHeader(CommandSessionSetup)
	header.Credits = 127

	negResp := gss.NewNegTokenResp()
	negResp.ResponseToken = responseToken

	ss2req := SessionSetup2Request{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		SecurityBufferOffset: 88,
		SecurityBlob:         negResp,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
		Capabilities:         0,
		Channel:              0,
	}

	return &ss2req, nil
}

package smb

import (
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github/izouxv/smbapi/gss"
	"github/izouxv/smbapi/ntlmssp"
	"github/izouxv/smbapi/smb/encoder"
)

type SessionSetup1Request struct {
	Header
	StructureSize        uint16
	Flags                byte
	SecurityMode         byte
	Capabilities         uint32
	Channel              uint32
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	PreviousSessionID    uint64
	SecurityBlob         *gss.NegTokenInit
}

type SessionSetup1Response struct {
	Header
	StructureSize        uint16
	Flags                uint16
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	SecurityBlob         *gss.NegTokenResp
}

func (r *SessionSetup1Request) challengeData() ntlmssp.Challenge {
	ServerChallenge := rand.Uint64()

	challenge := ntlmssp.NewChallenge(ServerChallenge)
	challenge.TargetName = encoder.ToUnicode("testGoGo")

	if true {
		type AvPair struct {
			AvID  uint16
			AvLen uint16 `smb:"len:Value"`
			Value []byte
		}
		// var infos []ntlmssp.AvPair
		var infos ntlmssp.AvPairSlice

		ft := uint64(time.Now().UnixNano()) / 100
		timestamp := make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
		infos = append(infos, ntlmssp.AvPair{
			AvID:  ntlmssp.MsvAvTimestamp,
			AvLen: 8,
			Value: timestamp,
		})

		infos = append(infos, ntlmssp.AvPair{
			AvID:  ntlmssp.MsvAvEOL,
			AvLen: 8,
			Value: timestamp,
		})

		challenge.TargetInfo = &infos
	}
	return challenge

}

func (data *SessionSetup1Request) ServerAction(ctx *DataCtx) (interface{}, error) {
	resp1 := SessionSetup1Response{
		SecurityBlob: &gss.NegTokenResp{},
	}

	resp1.Header = data.Header
	resp1.Header.Credits = 33
	resp1.Header.Status = StatusLogonFailure
	resp1.Header.SessionID = ctx.session.sessionID
	resp1.StructureSize = 9
	resp1.SecurityBufferOffset = 0x48
	resp1.Header.Flags = SMB2_FLAGS_RESPONSE

	var ntlmsspneg ntlmssp.Negotiate
	if err := encoder.Unmarshal(data.SecurityBlob.Data.MechToken, &ntlmsspneg); err != nil {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}
	// logx.Printf("domain name: %v", ntlmsspneg.DomainName)
	// logx.Printf("domain name: %v", ntlmsspneg.Workstation)

	if true {
		negotiateFlagmltmsspmsNEGOTIATELMKEY := 1 << 7
		if int(ntlmsspneg.NegotiateFlags)&negotiateFlagmltmsspmsNEGOTIATELMKEY == negotiateFlagmltmsspmsNEGOTIATELMKEY {
			return &resp1, nil
			// return errors.New("Only NTLM v2 is supported, but server requested v1 (mltmsspms_NEGOTIATE_LM_KEY)")
		}
	}

	// ServerChallenge := rand.Uint64()
	// ctx.session.ServerChallenge = ServerChallenge
	// challenge := ntlmssp.NewChallenge(ServerChallenge)
	// challenge.TargetName = encoder.ToUnicode("testGoGo")

	challenge := data.challengeData()

	if true {
		type AvPair struct {
			AvID  uint16
			AvLen uint16 `smb:"len:Value"`
			Value []byte
		}
		// var infos []ntlmssp.AvPair
		var infos ntlmssp.AvPairSlice

		ft := uint64(time.Now().UnixNano()) / 100
		timestamp := make([]byte, 8)
		binary.LittleEndian.PutUint64(timestamp, ft)
		infos = append(infos, ntlmssp.AvPair{
			AvID:  ntlmssp.MsvAvTimestamp,
			AvLen: 8,
			Value: timestamp,
		})
		infos = append(infos, ntlmssp.AvPair{
			AvID:  ntlmssp.MsvAvEOL,
			AvLen: 0,
		})

		challenge.TargetInfo = &infos
	}

	ctx.session.ServerChallenge = challenge.ServerChallenge
	challengeData, err := encoder.Marshal(&challenge)
	if err != nil {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}

	resp1.SecurityBlob = &gss.NegTokenResp{
		NegResult:     asn1.Enumerated(gss.Accept_incomplete),
		ResponseToken: challengeData,
		SupportedMech: myMech(),
	}
	resp1.Header.Status = StatusMoreProcessingRequired

	return &resp1, nil

}

func (requestSetUp1 *SessionSetup1Request) ClientAction(s *SessionC, setupResponse1 *SessionSetup1Response) error {
	if setupResponse1.Header.Status != StatusMoreProcessingRequired {
		// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/115b551a-dcd7-4ff2-8c59-a334b92e01c0
		status, _ := StatusMap[setupResponse1.Header.Status]
		return errors.New(fmt.Sprintf("NT Status Error: %s\n", status))
	}
	s.sessionID = setupResponse1.Header.SessionID

	challenge := ntlmssp.NewChallenge(0)
	resp := setupResponse1.SecurityBlob
	if err := encoder.Unmarshal(resp.ResponseToken, &challenge); err != nil {
		s.Debug("", err)
		return err
	}
	s.Challenge = challenge

	return nil
}

func (s *SessionC) NewSessionSetup1Request(mechType gss.MechTypeOid) SessionSetup1Request {
	header := s.newHeader(CommandSessionSetup)

	ntlmsspneg := ntlmssp.NewNegotiate(s.options.Domain, s.options.Workstation)
	data, err := encoder.Marshal(ntlmsspneg)
	if err != nil {
		panic(-1)
	}
	negInit, _ := gss.NewNegTokenInit(mechType)
	negInit.Data.MechToken = data

	switch mechType {
	case gss.NtLmSSPMechTypeOid:
	}
	return SessionSetup1Request{
		Header:               header,
		StructureSize:        25,
		Flags:                0x00,
		SecurityMode:         byte(SecurityModeSigningEnabled),
		SecurityBufferOffset: 88,
		SecurityBlob:         negInit,
		Capabilities:         0,
		Channel:              0,
		SecurityBufferLength: 0,
		PreviousSessionID:    0,
	}
}

package smb

import (
	cryptorand "crypto/rand"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"github/izouxv/smbapi/gss"

	"github.com/izouxv/logx"
)

const (
	// kMaxTransactSize     = 0x800000
	// kMaxTransactSizeSmb1 = 4194304
	kMaxTransactSize     = 1048576
	kMaxTransactSizeSmb1 = 1048576
)

// var gSPNEGOResponse = []byte{0x60, 0x48, 0x06, 0x06,
// 	0x2b, 0x06, 0x01, 0x05, 0x05, 0x02, 0xa0, 0x3e, 0x30, 0x3c, 0xa0, 0x0e, 0x30, 0x0c, 0x06, 0x0a,
// 	0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0a,
// 	0xa3, 0x2a, 0x30, 0x28, 0xa0, 0x26, 0x1b, 0x24, 0x6e, 0x6f, 0x74, 0x5f, 0x64, 0x65, 0x66, 0x69, 0x6e, 0x65, 0x64, 0x5f, 0x69, 0x6e, 0x5f, 0x52, 0x46, 0x43, 0x34, 0x31, 0x37, 0x38, 0x40, 0x70, 0x6c, 0x65, 0x61, 0x73, 0x65, 0x5f, 0x69, 0x67, 0x6e, 0x6f, 0x72, 0x65}

const (
	SMB2_GLOBAL_CAP_DFS                = 0x00000001
	SMB2_GLOBAL_CAP_LEASING            = 0x00000002
	SMB2_GLOBAL_CAP_LARGE_MTU          = 0x00000004
	SMB2_GLOBAL_CAP_MULTI_CHANNEL      = 0x00000008
	SMB2_GLOBAL_CAP_PERSISTENT_HANDLES = 0x00000010
	SMB2_GLOBAL_CAP_DIRECTORY_LEASING  = 0x00000020
	SMB2_GLOBAL_CAP_ENCRYPTION         = 0x00000040
)

func timeToFiletime(tm time.Time) uint64 {
	nsec := tm.UnixNano()
	// convert into 100-nanosecond
	nsec /= 100
	// change starting time to January 1, 1601
	nsec += 116444736000000000
	return uint64(nsec)
}

type HeaderSmb1 struct {
	ProtocolID  []byte `smb:"fixed:4"`
	SmbCommand  uint8  //0x72: negotiate protocol
	NtStatus    uint32
	Flags       uint8 //case sensitivity
	Flags2      uint16
	PricessId   uint16
	Signature   []byte `smb:"fixed:8"`
	Reserved    uint16
	TreeId      uint16
	ProcessId   uint16
	UserId      uint16
	MultiplexId uint16
}
type NegotiateSmb1Request struct {
	HeaderSmb1
	WordCount uint8
	ByteCount uint16
	// Dialects  []uint16
}
type NegotiateRequest struct {
	Header
	StructureSize   uint16
	DialectCount    uint16 `smb:"count:Dialects"`
	SecurityMode    uint16
	Reserved        uint16
	Capabilities    uint32
	ClientGuid      []byte `smb:"fixed:16"`
	ClientStartTime uint64
	Dialects        []uint16
}

var myMech = func() asn1.ObjectIdentifier {
	myMechType := gss.NtLmSSPMechTypeOid
	// Check for NTLMSSP support
	mySSPOID, err := gss.ObjectIDStrToInt(myMechType)
	if err != nil {
		panic(-1)
	}
	return asn1.ObjectIdentifier(mySSPOID)
}

type NegotiateResponse struct {
	Header
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16
	ServerGuid           []byte `smb:"fixed:16"`
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16 `smb:"offset:SecurityBlob"`
	SecurityBufferLength uint16 `smb:"len:SecurityBlob"`
	Reserved2            uint32
	SecurityBlob         *gss.NegTokenInit
}

func (data *NegotiateSmb1Request) ServerAction(ctx *DataCtx) (interface{}, error) {

	req := &NegotiateRequest{
		Dialects: []uint16{DialectSmb_2_0_2},
	}

	resp := NegotiateResponse{
		Header:       newHeader(CommandNegotiate, 0, 0),
		SecurityBlob: &gss.NegTokenInit{},
	}
	resp.Header.CreditCharge = 0
	resp.Header.Credits = 1
	resp.Header.Status = StatusOk
	resp.Header.Flags = SMB2_FLAGS_RESPONSE
	resp.Header.Reserved = 1

	if true {
		//check dialect
		foundMyVer := false
		for _, d := range req.Dialects {
			if d == DialectSmb_2_1 || d == DialectSmb_2_0_2 {
				foundMyVer = true
			}
		}
		if !foundMyVer {
			return ERR(req.Header, STATUS_NOT_SUPPORTED)
		}
	}

	// ctx.session.dialect = uint16(DialectSmb_2_0_2)
	// ctx.session.dialect = uint16(DialectSmb_2_1)

	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return ERR(req.Header, STATUS_INVALID_PARAMETER)
	}
	resp.SecurityBlob.OID = asn1.ObjectIdentifier(spnegoOID)
	resp.SecurityBlob.Data.MechTypes = []asn1.ObjectIdentifier{myMech()}
	resp.SecurityMode = SecurityModeSigningEnabled //| SecurityModeSigningRequired 这个需要验证header的signature

	var gServerGuid []byte = func() []byte {
		// type GUID [16]byte
		var g GUID

		mustReadRand := func(dst []byte) {
			_, err := cryptorand.Read(dst[:])
			if err != nil {
				panic(err)
			}
		}

		mustReadRand(g[:])
		return g[:]
	}()

	resp.StructureSize = 0x41
	// resp.SecurityMode = 0x03
	resp.DialectRevision = DialectSmb2_ALL
	resp.ServerGuid = gServerGuid
	resp.Capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU
	resp.MaxTransactSize = kMaxTransactSizeSmb1
	resp.MaxReadSize = kMaxTransactSizeSmb1
	resp.MaxWriteSize = kMaxTransactSizeSmb1
	resp.SystemTime = timeToFiletime(time.Now())
	resp.SecurityBufferOffset = 0x80
	// resp.SecurityBufferLength = uint16(len(gSPNEGOResponse))

	return &resp, nil

	// return req.serverAction(ctx, resp)
}

func (data *NegotiateRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	resp := NegotiateResponse{
		SecurityBlob: &gss.NegTokenInit{},
	}
	resp.Header = data.Header
	resp.Header.Credits = 1
	resp.Header.Status = StatusOk
	resp.StructureSize = 65
	resp.Header.Flags = SMB2_FLAGS_RESPONSE

	if true {
		//check dialect
		foundMyVer := false
		for _, d := range data.Dialects {
			if d == DialectSmb_2_1 {
				foundMyVer = true
			}
		}
		if !foundMyVer {
			return ERR(data.Header, STATUS_NOT_SUPPORTED)
		}
	}

	logx.Printf("clientSupportDialect: %v", data.Dialects)
	ctx.session.dialect = uint16(DialectSmb_2_1)
	return data.serverAction(ctx, resp)
}

func (data *NegotiateRequest) serverAction(ctx *DataCtx, resp NegotiateResponse) (interface{}, error) {

	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}
	resp.SecurityBlob.OID = asn1.ObjectIdentifier(spnegoOID)
	resp.SecurityBlob.Data.MechTypes = []asn1.ObjectIdentifier{myMech()}
	resp.SecurityMode = SecurityModeSigningEnabled //| SecurityModeSigningRequired 这个需要验证header的signature
	resp.DialectRevision = ctx.session.dialect

	var gServerGuid []byte = func() []byte {
		// type GUID [16]byte
		var g GUID

		mustReadRand := func(dst []byte) {
			_, err := cryptorand.Read(dst[:])
			if err != nil {
				panic(err)
			}
		}

		mustReadRand(g[:])
		return g[:]
	}()

	resp.ServerGuid = gServerGuid
	resp.Capabilities = SMB2_GLOBAL_CAP_DFS | SMB2_GLOBAL_CAP_LEASING | SMB2_GLOBAL_CAP_LARGE_MTU //| SMB2_GLOBAL_CAP_DIRECTORY_LEASING // TODO: check 3.3.5.4, page 259

	resp.MaxTransactSize = kMaxTransactSize
	resp.MaxReadSize = kMaxTransactSize
	resp.MaxWriteSize = kMaxTransactSize
	resp.SystemTime = timeToFiletime(time.Now())
	resp.SecurityBufferOffset = 0x80
	// resp.SecurityBufferLength = uint16(len(gSPNEGOResponse))

	return &resp, nil
}

func (negReq *NegotiateRequest) ClientAction(s *SessionC, negRes *NegotiateResponse) error {
	myMechType := gss.NtLmSSPMechTypeOid

	if negRes.Header.Status != StatusOk {
		return errors.New(fmt.Sprintf("NT Status Error: %d\n", negRes.Header.Status))
	}
	// Check SPNEGO security blob
	spnegoOID, err := gss.ObjectIDStrToInt(gss.SpnegoOid)
	if err != nil {
		return err
	}
	oid := negRes.SecurityBlob.OID
	if !oid.Equal(asn1.ObjectIdentifier(spnegoOID)) {
		return errors.New(fmt.Sprintf(
			"Unknown security type OID [expecting %s]: %s\n",
			gss.SpnegoOid,
			negRes.SecurityBlob.OID))
	}

	// Check for NTLMSSP support
	mySSPOID, err := gss.ObjectIDStrToInt(myMechType)
	if err != nil {
		s.Debug("", err)
		return err
	}

	hasMySSP := false
	for _, mechType := range negRes.SecurityBlob.Data.MechTypes {
		if mechType.Equal(asn1.ObjectIdentifier(mySSPOID)) {
			hasMySSP = true
			break
		}
	}
	if !hasMySSP {
		return errors.New("Server does not support NTLMSSP")
	}

	s.securityMode = negRes.SecurityMode
	s.dialect = negRes.DialectRevision

	// Determine whether signing is required
	mode := uint16(s.securityMode)
	if mode&SecurityModeSigningEnabled > 0 {
		if mode&SecurityModeSigningRequired > 0 {
			s.IsSigningRequired = true
		} else {
			s.IsSigningRequired = false
		}
	} else {
		s.IsSigningRequired = false
	}
	return nil
}

func (s *SessionC) NewNegotiateRequest() *NegotiateRequest {
	header := s.newHeader(CommandNegotiate)
	dialects := []uint16{
		uint16(DialectSmb_2_1),
		uint16(DialectSmb_3_0),
		uint16(DialectSmb_3_0_2),
	}
	return &NegotiateRequest{
		Header:          header,
		StructureSize:   36,
		DialectCount:    uint16(len(dialects)),
		SecurityMode:    SecurityModeSigningEnabled,
		Reserved:        0,
		Capabilities:    0,
		ClientGuid:      make([]byte, 16),
		ClientStartTime: 0,
		Dialects:        dialects,
	}
}

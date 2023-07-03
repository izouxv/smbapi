package smb

import (
	"github/izouxv/smbapi/smb/encoder"
)

// type SMB2_CREATE_CONTEXT_REQUEST_TYPE string

// const (
// 	SMB2_CREATE_EA_BUFFER                    SMB2_CREATE_CONTEXT_REQUEST_TYPE = "ExtA"
// 	SMB2_CREATE_SD_BUFFER                    SMB2_CREATE_CONTEXT_REQUEST_TYPE = "SecD"
// 	SMB2_CREATE_DURABLE_HANDLE_REQUEST       SMB2_CREATE_CONTEXT_REQUEST_TYPE = "DHnQ"
// 	SMB2_CREATE_DURABLE_HANDLE_RECONNECT     SMB2_CREATE_CONTEXT_REQUEST_TYPE = "DHnC"
// 	SMB2_CREATE_ALLOCATION_SIZE              SMB2_CREATE_CONTEXT_REQUEST_TYPE = "AISi"
// 	SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST SMB2_CREATE_CONTEXT_REQUEST_TYPE = "MxAc"
// 	SMB2_CREATE_TIMEWARP_TOKEN               SMB2_CREATE_CONTEXT_REQUEST_TYPE = "TWrp"
// 	SMB2_CREATE_QUERY_ON_DISK_ID             SMB2_CREATE_CONTEXT_REQUEST_TYPE = "QFid"
// 	SMB2_CREATE_REQUEST_LEASE                SMB2_CREATE_CONTEXT_REQUEST_TYPE = "RqLs"
// 	SMB2_CREATE_REQUEST_LEASE_V2             SMB2_CREATE_CONTEXT_REQUEST_TYPE = "RqLs"
// 	SMB2_CREATE_DURABLE_HANDLE_REQUEST_V2    SMB2_CREATE_CONTEXT_REQUEST_TYPE = "DH2Q"
// 	SMB2_CREATE_DURABLE_HANDLE_RECONNECT_V2  SMB2_CREATE_CONTEXT_REQUEST_TYPE = "DH2C"
// )

type SMB2_CREATE_CONTEXT_RESPONSE_TYPE string

const (
	// SMB2_CREATE_DURABLE_HANDLE_RESPONSE_TAG       SMB2_CREATE_CONTEXT_RESPONSE_TYPE = "DHnQ"
	SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE_TAG SMB2_CREATE_CONTEXT_RESPONSE_TYPE = "MxAc"
	// SMB2_CREATE_QUERY_ON_DISK_ID_TAG              SMB2_CREATE_CONTEXT_RESPONSE_TYPE = "QFid"
	// SMB2_CREATE_RESPONSE_LEASE_TAG                SMB2_CREATE_CONTEXT_RESPONSE_TYPE = "RqLs"
	SMB2_APPL_CREATE_CONTENT_TAG SMB2_CREATE_CONTEXT_RESPONSE_TYPE = "AAPL"
)

type SMB2_CREATE_CONTEXT_REQUEST struct {
	Next       uint32
	TagOffset  uint16 `smb:"offset:Tag"`
	TagLength  uint16 `smb:"len:Tag"`
	Reserved   uint16
	DataOffset uint16 `smb:"offset:Data"`
	DataLength uint32 `smb:"len:Data"`
	Tag        []byte
	Reserved2  uint32
	Data       []byte
}

func (s *SMB2_CREATE_CONTEXT_REQUEST) Action(actioncb func(SMB2_CREATE_CONTEXT_RESPONSE_TYPE, interface{}) (interface{}, error)) []byte {
	tag := SMB2_CREATE_CONTEXT_RESPONSE_TYPE(s.Tag)
	// logx.Printf("create ext type : %v", tag)

	var data interface{}
	switch tag {
	// case SMB2_CREATE_DURABLE_HANDLE_RESPONSE_TAG:
	case SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE_TAG:
		data = &SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST{}
	// case SMB2_CREATE_QUERY_ON_DISK_ID_TAG:
	// case SMB2_CREATE_RESPONSE_LEASE_TAG:
	case SMB2_APPL_CREATE_CONTENT_TAG:
		data = &SMB2_APPL_CREATE_CONTENT_TAG_REQUEST{}
	default:
		return nil
	}
	resp, err := actioncb(tag, data)
	if err != nil {
		return nil
	}
	respBuf, err := encoder.Marshal(resp)
	if err != nil {
		return nil
	}
	s.Data = respBuf
	sBuf, err := encoder.Marshal(s)
	if err != nil {
		return nil
	}
	return sBuf
}

type SMB2_CREATE_QUERY_MAXIMAL_ACCESS_REQUEST struct {
	Timestamp uint64
}
type SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE struct {
	QueryStatus   uint32
	MaximalAccess AccessMask //MaximalAccess
}
type SMB2_APPL_CREATE_CONTENT_TAG_REQUEST struct {
	ServerQuery     uint32
	Reserved        uint32
	QueryBitmask    uint64
	ClientServerCap uint64
}
type SMB2_APPL_CREATE_CONTENT_TAG_RESPONSE struct {
	ServerQuery     uint32
	Reserved        uint32
	QueryBitmask    uint64
	ClientServerCap uint64
	VolumeCap       uint64
	ModelStringLen  uint16 `smb:"len:ModelString"`
	ModelString     uint16
}

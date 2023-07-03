package smb

import (
	"encoding/binary"

	"github/izouxv/smbapi/smb/encoder"
)

const ProtocolSmb = "\xFFSMB"
const ProtocolSmb2 = "\xFESMB"

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb/6ab6ca20-b404-41fd-b91a-2ed39e3762ea

type Status uint32

const (
	StatusOk                        Status = 0x00000000
	STATUS_PENDING                  Status = 0x00000103
	StatusMoreProcessingRequired    Status = 0xc0000016
	StatusInvalidParameter          Status = 0xc000000d
	StatusLogonFailure              Status = 0xc000006d
	StatusUserSessionDeleted        Status = 0xc0000203
	STATUS_INVALID_SMB              Status = 0x00010002
	STATUS_SMB_BAD_TID              Status = 0x00050002
	STATUS_SMB_BAD_COMMAND          Status = 0x00160002
	STATUS_SMB_BAD_UID              Status = 0x005B0002
	STATUS_BUFFER_OVERFLOW          Status = 0x80000005
	STATUS_NO_MORE_FILES            Status = 0x80000006
	STATUS_NO_SUCK_FILE             Status = 0xC000000f
	STATUS_STOPPED_ON_SYMLINK       Status = 0x8000002D
	STATUS_NOT_IMPLEMENTED          Status = 0xC0000002
	STATUS_INVALID_PARAMETER        Status = 0xC000000D
	STATUS_MORE_PROCESSING_REQUIRED Status = 0xC0000016
	STATUS_ACCESS_DENIED            Status = 0xC0000022
	STATUS_BUFFER_TOO_SMALL         Status = 0xC0000023
	STATUS_OBJECT_NAME_NOT_FOUND    Status = 0xC0000034
	STATUS_OBJECT_PATH_NOT_FOUND    Status = 0xC000003A
	STATUS_IO_TIMEOUT               Status = 0xC00000B5
	STATUS_FILE_IS_A_DIRECTORY      Status = 0xC00000BA
	STATUS_NOT_SUPPORTED            Status = 0xC00000BB
	STATUS_NETWORK_SESSION_EXPIRED  Status = 0xC000035C
	STATUS_SMB_TOO_MANY_UIDS        Status = 0xC000205A
	STATUS_NETWORK_NAME_DELETED     Status = 0xC00000C9
	STATUS_FILE_CLOSED              Status = 0xC0000128
	STATUS_UNSUCCESSFUL             Status = 0xC0000001
	STATUS_END_OF_FILE              Status = 0xC0000011
)

var StatusMap = map[Status]string{
	StatusOk:                     "OK",
	StatusMoreProcessingRequired: "More Processing Required",
	StatusInvalidParameter:       "Invalid Parameter",
	StatusLogonFailure:           "Logon failed",
	StatusUserSessionDeleted:     "User session deleted",
}

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8

const DialectSmb_2_0_2 = 0x0202
const DialectSmb_2_1 = 0x0210
const DialectSmb_3_0 = 0x0300
const DialectSmb_3_0_2 = 0x0302
const DialectSmb_3_1_1 = 0x0311
const DialectSmb2_ALL = 0x02FF

type Command uint16

const (
	CommandNegotiate Command = iota
	CommandSessionSetup
	CommandLogoff
	CommandTreeConnect
	CommandTreeDisconnect
	CommandCreate
	CommandClose
	CommandFlush
	CommandRead
	CommandWrite
	CommandLock
	CommandIOCtl
	CommandCancel
	CommandEcho
	CommandFind //QueryDirectory
	CommandChangeNotify
	CommandQueryInfo
	CommandSetInfo
	CommandOplockBreak
)

func (c Command) String() string {
	switch c {
	case CommandNegotiate:
		return "CommandNegotiate"
	case CommandSessionSetup:
		return "CommandSessionSetup"
	case CommandLogoff:
		return "CommandLogoff"
	case CommandTreeConnect:
		return "CommandTreeConnect"
	case CommandTreeDisconnect:
		return "CommandTreeDisconnect"
	case CommandCreate:
		return "CommandCreate"
	case CommandClose:
		return "CommandClose"
	case CommandFlush:
		return "CommandFlush"
	case CommandRead:
		return "CommandRead"
	case CommandWrite:
		return "CommandWrite"
	case CommandLock:
		return "CommandLock"
	case CommandIOCtl:
		return "CommandIOCtl"
	case CommandCancel:
		return "CommandCancel"
	case CommandEcho:
		return "CommandEcho"
	case CommandFind:
		return "CommandQueryDirectory"
	case CommandChangeNotify:
		return "CommandChangeNotify"
	case CommandQueryInfo:
		return "CommandQueryInfo"
	case CommandSetInfo:
		return "CommandSetInfo"
	case CommandOplockBreak:
		return "CommandOplockBreak"
	default:
		return "NA"
	}
}

const (
	SecurityModeSigningEnabled  = 0x001 //When set, indicates that security signatures are enabled on the client. The server MUST ignore this bit.
	SecurityModeSigningRequired = 0x002 //When set, indicates that security signatures are required by the client.
)

// const (
// 	_ byte = iota
// 	ShareTypeDisk
// 	ShareTypePipe
// 	ShareTypePrint
// )

// const (
// 	ShareFlagManualCaching            uint32 = 0x00000000
// 	ShareFlagAutoCaching              uint32 = 0x00000010
// 	ShareFlagVDOCaching               uint32 = 0x00000020
// 	ShareFlagNoCaching                uint32 = 0x00000030
// 	ShareFlagDFS                      uint32 = 0x00000001
// 	ShareFlagDFSRoot                  uint32 = 0x00000002
// 	ShareFlagRestriceExclusiveOpens   uint32 = 0x00000100
// 	ShareFlagForceSharedDelete        uint32 = 0x00000200
// 	ShareFlagAllowNamespaceCaching    uint32 = 0x00000400
// 	ShareFlagAccessBasedDirectoryEnum uint32 = 0x00000800
// 	ShareFlagForceLevelIIOplock       uint32 = 0x00001000
// 	ShareFlagEnableHashV1             uint32 = 0x00002000
// 	ShareFlagEnableHashV2             uint32 = 0x00004000
// 	ShareFlagEncryptData              uint32 = 0x00008000
// )

// const (
// 	ShareCapDFS                    uint32 = 0x00000008
// 	ShareCapContinuousAvailability uint32 = 0x00000010
// 	ShareCapScaleout               uint32 = 0x00000020
// 	ShareCapCluster                uint32 = 0x00000040
// 	ShareCapAsymmetric             uint32 = 0x00000080
// )

type HeadFlags uint32

const (
	SMB2_FLAGS_RESPONSE         HeadFlags = 0x00000001
	SMB2_FLAGS_ASYNC_COMMAND    HeadFlags = 0x00000002
	SMB2_FLAGS_SIGNED           HeadFlags = 0x00000008
	SMB2_FLAGS_PRIORITY_MASK    HeadFlags = 0x00000070
	SMB2_FLAGS_DFS_OPERATIONS   HeadFlags = 0x10000000
	SMB2_FLAGS_REPLAY_OPERATION HeadFlags = 0x20000000
)

type Header struct {
	ProtocolID   []byte `smb:"fixed:4"`
	HeaderLength uint16 //StructureSize
	CreditCharge uint16
	Status       Status
	Command      Command
	Credits      uint16
	Flags        HeadFlags //HeadFlags
	NextCommand  uint32    // Chain Offset 就是这段的大小, 最后一段的时候为0,
	MessageID    uint64
	Reserved     uint32
	TreeID       uint32
	SessionID    uint64
	Signature    []byte `smb:"fixed:16"`
}

var _ encoder.BinaryMarshallable = HeadFlags(0)

func (c HeadFlags) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c HeadFlags) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

var _ encoder.BinaryMarshallable = Status(0)

func (c Status) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c Status) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

var _ encoder.BinaryMarshallable = Command(0)

func (c Command) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c Command) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

var _ encoder.BinaryMarshallable = Command(0)

func MarshalBinary[
	T Command |
		Status |
		CreateOptions |
		FileAttributes |
		AccessMask |
		HeadFlags |
		PDUType |
		CreateDisposition |
		FileInformationClass |
		CompletionFilter |
		ShareAccess |
		FindFlags |
		CreateAction |
		InfoType](
	base T, meta *encoder.Metadata, check encoder.BinaryMarshallable) ([]byte, error) {

	size := binary.Size(base)
	switch size {
	default:
		timestamp := make([]byte, 2)
		binary.LittleEndian.PutUint16(timestamp, uint16(base))
		return timestamp, nil
	case 4:
		timestamp := make([]byte, 4)
		binary.LittleEndian.PutUint32(timestamp, uint32(base))
		return timestamp, nil
	case 1:
		timestamp := make([]byte, 1)
		timestamp[0] = uint8(base)
		return timestamp, nil
	}
}

func UnmarshalBinary[
	T Command |
		Status |
		CreateOptions |
		FileAttributes |
		AccessMask |
		HeadFlags |
		PDUType |
		CreateDisposition |
		FileInformationClass |
		CompletionFilter |
		ShareAccess |
		FindFlags |
		CreateAction |
		InfoType](
	base T, data []byte, meta *encoder.Metadata, check encoder.BinaryMarshallable) (T, error) {
	size := binary.Size(base)
	switch size {
	default:
		num := binary.LittleEndian.Uint16(data)
		meta.CurrOffset += uint64(binary.Size(num))
		c := T(num)
		return c, nil
	case 4:
		num := binary.LittleEndian.Uint32(data)
		meta.CurrOffset += uint64(binary.Size(num))
		c := T(num)
		return c, nil
	case 1:
		num := uint8(data[0])
		meta.CurrOffset += uint64(binary.Size(num))
		c := T(num)
		return c, nil
	}
}

type ErrResponse struct {
	Header
	StructureSize     uint16
	ErrorContextCount uint8
	Reserved          uint8
	ByteCount         uint32
	ErrorData         uint8
}

func ERR(header Header, stat Status) (interface{}, error) {
	header.Flags = SMB2_FLAGS_RESPONSE
	header.Status = stat
	return ErrResponse{
		Header:        header,
		StructureSize: 0x0009,
	}, nil
}

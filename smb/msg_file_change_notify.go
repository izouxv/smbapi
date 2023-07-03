package smb

import "github/izouxv/smbapi/smb/encoder"

// request_CHANGE_NOTIFY
type CompletionFilter uint32

const (
	FILE_NOTIFY_CHANGE_FILE_NAME    CompletionFilter = 0x00000001
	FILE_NOTIFY_CHANGE_DIR_NAME     CompletionFilter = 0x00000002
	FILE_NOTIFY_CHANGE_ATTRIBUTES   CompletionFilter = 0x00000004
	FILE_NOTIFY_CHANGE_SIZE         CompletionFilter = 0x00000008
	FILE_NOTIFY_CHANGE_LAST_WRITE   CompletionFilter = 0x00000010
	FILE_NOTIFY_CHANGE_LAST_ACCESS  CompletionFilter = 0x00000020
	FILE_NOTIFY_CHANGE_CREATION     CompletionFilter = 0x00000040
	FILE_NOTIFY_CHANGE_EA           CompletionFilter = 0x00000080
	FILE_NOTIFY_CHANGE_SECURITY     CompletionFilter = 0x00000100
	FILE_NOTIFY_CHANGE_STREAM_NAME  CompletionFilter = 0x00000200
	FILE_NOTIFY_CHANGE_STREAM_SIZE  CompletionFilter = 0x00000400
	FILE_NOTIFY_CHANGE_STREAM_WRITE CompletionFilter = 0x00000800
)

var _ encoder.BinaryMarshallable = CompletionFilter(0)

func (c CompletionFilter) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c CompletionFilter) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

func init() {
	commandRequestMap[CommandChangeNotify] = func() DataI {
		return &ChangeNotifyRequest{}
	}
}

type ChangeNotifyRequest struct {
	Header
	StructureSize      uint16
	Flags              uint16
	OutputBufferLength uint32
	FileId             GUID
	CompletionFilter   CompletionFilter //CompletionFilter
	Reserved           uint32
}

type ChangeNotifyResponse struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16 `smb:"offset:OutputBuffer"`
	OutputBufferLength uint32 `smb:"len:OutputBuffer"`
	OutputBuffer       []byte
}

func (data *ChangeNotifyRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	data.Header.Status = STATUS_PENDING
	ctx.session.notify[data.FileId] = data
	return ERR(data.Header, STATUS_PENDING)
}

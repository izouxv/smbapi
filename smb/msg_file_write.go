package smb

func init() {
	commandRequestMap[CommandWrite] = func() DataI {
		return &WriteRequest{}
	}
}

//CommandWrite

type WriteRequest struct {
	Header
	StructureSize          uint16
	DataOffset             uint16 `smb:"offset:Data"`
	DataLength             uint32 `smb:"len:Data"`
	FileOffset             uint64
	FileId                 GUID
	Channel                uint32
	RemainingBytes         uint32
	WriteChannelInfoOffset uint16 `smb:"offset:WriteChannelInfo"`
	WriteChannelInfoLength uint16 `smb:"len:WriteChannelInfo"`
	Flags                  uint32
	Data                   []byte
	// WriteChannelInfo       []byte
}

type WriteResponse struct {
	Header
	StructureSize          uint16
	Reserved               uint16
	Count                  uint32
	Remaining              uint32
	WriteChannelInfoOffset uint16 `smb:"offset:WriteChannelInfo"`
	WriteChannelInfoLength uint16 `smb:"len:WriteChannelInfo"`
	WriteChannelInfo       []byte
}

func (data *WriteRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE

	if data.Header.Flags&SMB2_FLAGS_PRIORITY_MASK == SMB2_FLAGS_PRIORITY_MASK {
		return ERR(data.Header, STATUS_NOT_SUPPORTED)
	}

	if data.DataLength > kMaxTransactSize ||
		data.DataLength == 0 ||
		// data.Channel != 0 ||
		len(data.Data) == 0 ||
		len(data.Data) != int(data.DataLength) {
		return ERR(data.Header, StatusInvalidParameter)
	}

	fileid := ctx.FileID(data.FileId)
	webfile, ok := ctx.session.openedFiles[fileid]
	if !ok {
		return ERR(data.Header, STATUS_FILE_CLOSED)
	}

	if fileid.IsSvrSvc(ctx.session) {
		return DcerpcWrite(ctx, data)
	}

	_, err := webfile.Seek(int64(data.FileOffset), 0)
	if err != nil {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}
	doneSize, err := webfile.Write(data.Data)
	if err != nil {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}

	resp := WriteResponse{
		Count:         uint32(doneSize),
		Header:        data.Header,
		StructureSize: 17,
	}
	return &resp, nil
}

// //////////////////////////////////////////////////////////////////////
func NewWriteResponse() WriteResponse {
	return WriteResponse{}
}

// Channel属性
const (
	SMB2_CHANNEL_NONE               = 0x00000000
	SMB2_CHANNEL_RDMA_V1            = 0x00000001
	SMB2_CHANNEL_RDMA_V1_INVALIDATE = 0x00000002
	SMB2_CHANNEL_RDMA_TRANSFORM     = 0x00000003
)

// 写入请求
func (c *SessionC) NewWriteRequest(treeId uint32, fileId, buf []byte) WriteRequest {
	smb2Header := c.newHeader(CommandWrite)
	smb2Header.Credits = 127
	smb2Header.TreeID = treeId
	return WriteRequest{
		Header:        smb2Header,
		StructureSize: 49,
		// FileId:         fileId,
		Channel:        SMB2_CHANNEL_NONE,
		RemainingBytes: 0,
		Flags:          0,
		Data:           buf,
	}
}

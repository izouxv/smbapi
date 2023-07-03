package smb

import "io"

func init() {
	commandRequestMap[CommandRead] = func() DataI {
		return &ReadRequest{}
	}
}

//CommandRead

type ReadRequest struct {
	Header
	StructureSize         uint16
	Padding               uint8
	Flags                 uint8
	Length                uint32
	Offset                uint64
	FileId                GUID
	MinimumCount          uint32
	Channel               uint32
	RemainingBytes        uint32
	ReadChannelInfoOffset uint16 `smb:"offset:ReadChannelInfo"`
	ReadChannelInfoLength uint16 `smb:"len:ReadChannelInfo"`
	ReadChannelInfo       []byte
}

type ReadResponse struct {
	Header
	StructureSize uint16
	DataOffset    uint8 `smb:"offset:Data"`
	Reserved      uint8
	DataLength    uint32 `smb:"len:Data"`
	DataRemaining uint32
	Reserved2     uint32
	Data          []byte
}

func (data *ReadRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE

	fileid := ctx.FileID(data.FileId)
	webfile, ok := ctx.session.openedFiles[fileid]
	if !ok {
		return ERR(data.Header, STATUS_FILE_CLOSED)
	}

	if fileid.IsSvrSvc(ctx.session) {
		return DcerpcRead(ctx, data)
	}

	buffer := make([]byte, data.Length)
	_, err := webfile.Seek(int64(data.Offset), 0)
	if err != nil {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}
	n, err := webfile.Read(buffer)
	if n < int(data.MinimumCount) {
		return ERR(data.Header, STATUS_END_OF_FILE)
	}
	if err != nil && err != io.EOF {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}

	resp := ReadResponse{
		Header:        data.Header,
		StructureSize: 17,
		Data:          buffer[:n],
		DataOffset:    80,
		DataLength:    uint32(n),
	}
	return &resp, nil
}

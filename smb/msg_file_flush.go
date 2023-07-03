package smb

func init() {
	commandRequestMap[CommandFlush] = func() DataI {
		return &FlushRequest{}
	}
}

//CommandFlush

type FlushRequest struct {
	Header
	StructureSize uint16
	Reserved1     uint16
	Reserved2     uint32
	FileId        GUID
}

type FlushResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *FlushRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	resp := FlushResponse{
		Header:        data.Header,
		StructureSize: 0x001,
	}
	return &resp, nil
}

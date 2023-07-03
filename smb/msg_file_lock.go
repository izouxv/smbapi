package smb

func init() {
	commandRequestMap[CommandLock] = func() DataI {
		return &LockRequest{}
	}
}

//CommandLock

type LockRequest struct {
	Header
	StructureSize uint16
	Reserved1     uint16
	Reserved2     uint32
	FileId        GUID
}

type LockResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *LockRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	resp := LockResponse{
		Header:        data.Header,
		StructureSize: 0x0004,
	}
	return &resp, nil
}

package smb

func init() {
	commandRequestMap[CommandLogoff] = func() DataI {
		return &LogoffRequest{}
	}
}

// Logoff
type LogoffRequest struct {
	Header
	StructureSize uint16
	Reserved      uint16
}
type LogoffResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *LogoffRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	return &LogoffResponse{Header: data.Header}, nil
}

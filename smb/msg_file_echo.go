package smb

func init() {
	commandRequestMap[CommandEcho] = func() DataI {
		return &EchoRequest{}
	}
}

// ECHO
type EchoRequest struct {
	Header
	StructureSize uint16
	Reserved      uint16
}
type EchoResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *EchoRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	return &EchoResponse{
		Header:        data.Header,
		StructureSize: data.StructureSize,
	}, nil
}

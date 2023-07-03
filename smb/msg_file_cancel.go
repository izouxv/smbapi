package smb

func init() {
	commandRequestMap[CommandCancel] = func() DataI {
		return &CancelRequest{}
	}
}

// CancelRequest
type CancelRequest struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type CancelResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *CancelRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	resp := CancelResponse{
		Header:        data.Header,
		StructureSize: 17,
	}
	return &resp, nil
}

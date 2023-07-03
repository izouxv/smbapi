package smb

import (
	"errors"
)

func init() {
	commandRequestMap[CommandTreeDisconnect] = func() DataI {
		return &TreeDisconnectRequest{}
	}
}

// CommandTreeDisconnect
type TreeDisconnectRequest struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

type TreeDisconnectResponse struct {
	Header
	StructureSize uint16
	Reserved      uint16
}

func (data *TreeDisconnectRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	resp := TreeDisconnectResponse{Header: data.Header}
	return &resp, nil
}

func (s *SessionC) NewTreeDisconnectReq(treeId uint32) (TreeDisconnectRequest, error) {
	header := s.newHeader(CommandTreeDisconnect)
	header.TreeID = treeId
	return TreeDisconnectRequest{
		Header:        header,
		StructureSize: 4,
		Reserved:      0,
	}, nil
}

func NewTreeDisconnectRes() (TreeDisconnectResponse, error) {
	return TreeDisconnectResponse{}, nil
}

func (s *SessionC) TreeDisconnect(name string) error {

	var (
		treeid    uint32
		pathFound bool
	)
	for k, v := range s.trees {
		if k == name {
			treeid = v
			pathFound = true
			break
		}
	}

	if !pathFound {
		err := errors.New("Unable to find tree path for disconnect")
		s.Debug("", err)
		return err
	}

	s.Debug("Sending TreeDisconnect request ["+name+"]", nil)

	req, err := s.NewTreeDisconnectReq(treeid)
	var res TreeDisconnectResponse
	if err = s.RPC(req, &res); err != nil {
		return err
	}
	if res.Header.Status != StatusOk {
		return errors.New("Failed to disconnect from tree: " + StatusMap[res.Header.Status])
	}
	delete(s.trees, name)

	s.Debug("TreeDisconnect completed ["+name+"]", nil)
	return nil
}

package smb

import (
	"errors"
	"fmt"
	"strings"

	"github/izouxv/smbapi/smb/encoder"

	"github.com/izouxv/logx"
)

func init() {
	commandRequestMap[CommandTreeConnect] = func() DataI {
		return &TreeConnectRequest{}
	}
}

// TreeConnect
type TreeConnectRequest struct {
	Header
	StructureSize uint16
	TreeFlags     uint16 //Flags/Reserved
	PathOffset    uint16 `smb:"offset:Path"`
	PathLength    uint16 `smb:"len:Path"`
	Path          []byte
}
type request_TreeConnect_Extension struct {
	TreeConnectContextOffset  uint32 `smb:"offset:TreeConnectContext"`
	TreeConnectContextCount   uint16 `smb:"len:TreeConnectContext"`
	Reserved                  []byte `smb:"fixed:10"`
	PathNameOffset            uint16 `smb:"offset:PathName"`
	PathNameLength            uint16 `smb:"len:PathName"`
	TreeConnectContextsOffset uint16 `smb:"offset:TreeConnectContexts"`
	TreeConnectContextsLength uint16 `smb:"len:TreeConnectContexts"`
	TreeConnectContext        []byte
	PathName                  []byte
	TreeConnectContexts       *requset_TREE_CONNECT_CONTEXT
}
type requset_TREE_CONNECT_CONTEXT struct {
	ContextType uint16
	DataLength  uint16
	Reserved    uint32
	Data        []byte
}

type AccessMask uint32

const (
	//2.2.13.1.1
	FILE_READ_DATA   AccessMask = 0x00000001
	FILE_WRITE_DATA  AccessMask = 0x00000002
	FILE_APPEND_DATA AccessMask = 0x00000004
	FILE_READ_EA     AccessMask = 0x00000008

	FILE_WRITE_EA        AccessMask = 0x00000010
	FILE_DELETE_CHILD    AccessMask = 0x00000040
	FILE_EXECUTE         AccessMask = 0x00000020
	FILE_READ_ATTRIBUTES AccessMask = 0x00000080

	FILE_WRITE_ATTRIBUTES AccessMask = 0x00000100

	DELETE       AccessMask = 0x00010000
	READ_CONTROL AccessMask = 0x00020000
	WRITE_DAC    AccessMask = 0x00040000
	WRITE_OWNER  AccessMask = 0x00080000

	SYNCHRONIZE AccessMask = 0x00100000

	ACCESS_SYSTEM_SECURITY AccessMask = 0x01000000
	MAXIMUM_ALLOWED        AccessMask = 0x02000000

	GENERIC_ALL     AccessMask = 0x10000000
	GENERIC_EXECUTE AccessMask = 0x20000000
	GENERIC_WRITE   AccessMask = 0x40000000
	GENERIC_READ    AccessMask = 0x80000000
)

var AllAccessMask = (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |
	FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_EXECUTE | FILE_READ_ATTRIBUTES |
	FILE_WRITE_ATTRIBUTES |
	DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
	SYNCHRONIZE)

var _ encoder.BinaryMarshallable = (AccessMask)(0)

func (c AccessMask) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c AccessMask) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type TreeConnectResponse struct {
	Header
	StructureSize uint16
	ShareType     uint8
	Reserved      byte
	ShareFlags    uint32 //cache policy
	Capabilities  uint32
	Access_Mask   AccessMask //MaximalAccess
}

const (
	SMB2_TREE_CONNECT_FLAG_CLUSTER_RECONNECT uint16 = 1 << iota
	SMB2_TREE_CONNECT_FLAG_REDIRECT_TO_OWNER
	SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT
)

// var treeId uint32 = 0
var NamedPipeShareName = "IPC$"

func (data *TreeConnectRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	if data.TreeFlags&SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT == SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT {
		logx.Printf("SMB2_TREE_CONNECT_FLAG_EXTENSION_PRESENT")
	}
	path, err := encoder.FromUnicode(data.Path)
	if err != nil {
		return nil, err
	}

	if true {
		if path[0] != '\\' || path[1] != '\\' {
			panic(fmt.Errorf("invalid sdsdfsf '%s'", path))
		}
		path = path[2:]
		inx := strings.IndexByte(path, '\\')
		if inx < 0 {
			panic(fmt.Errorf("invalid sdsdfsf43"))
		}
		path = path[inx+1:]
		logx.Printf("path: %v", path)
	}

	path = strings.ToUpper(path)
	logx.Printf("path: %v", path)
	// tid := atomic.AddUint32(&ctx.s.treeId, 1)
	// tree := CreateTree(tid, path, "./")
	// ctx.s.addTrees([]*Tree{tree})

	SMB2_SHARE_TYPE_DISK := uint8(1)
	SMB2_SHARE_TYPE_PIPE := uint8(2)

	SMB2_SHAREFLAG_NO_CACHING := uint32(0x00000030)
	SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM := uint32(0x00000800)

	Access_Mask := (FILE_READ_DATA | FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_READ_EA |
		FILE_WRITE_EA | FILE_DELETE_CHILD | FILE_EXECUTE | FILE_READ_ATTRIBUTES |
		FILE_WRITE_ATTRIBUTES |
		DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER |
		SYNCHRONIZE | ACCESS_SYSTEM_SECURITY)

	ShareType := SMB2_SHARE_TYPE_DISK
	ShareFlags := SMB2_SHAREFLAG_NO_CACHING | SMB2_SHAREFLAG_ACCESS_BASED_DIRECTORY_ENUM

	if path == NamedPipeShareName {
		ShareFlags = SMB2_SHAREFLAG_NO_CACHING
		ShareType = SMB2_SHARE_TYPE_PIPE
	}

	anchor := ctx.session.GetAnchor(path)
	if anchor == nil {
		return ERR(data.Header, STATUS_NETWORK_NAME_DELETED)
	}
	data.Header.TreeID = anchor.tid
	data.Header.Status = StatusOk

	ctx.session.SetActiveAnchorKey(path)

	resp := TreeConnectResponse{
		Header:        data.Header,
		StructureSize: 0x0010,
		ShareType:     ShareType,
		ShareFlags:    ShareFlags,
		Access_Mask:   Access_Mask,
	}
	resp.Header.Status = StatusOk
	resp.Header.Signature = make([]byte, 16)
	resp.Header.Credits = 33
	return &resp, nil
}

func (requestSetUp2 *TreeConnectRequest) ClientAction(s *SessionC, negRes *TreeConnectResponse) error {
	return nil
}

func NewTreeConnectReq(s *SessionC, name string) (TreeConnectRequest, error) {
	header := s.newHeader(CommandTreeConnect)

	path := fmt.Sprintf("\\\\%s\\%s", s.options.Host, name)
	return TreeConnectRequest{
		Header:        header,
		StructureSize: 9,
		TreeFlags:     0,
		PathOffset:    0,
		PathLength:    0,
		Path:          encoder.ToUnicode(path),
	}, nil
}

func NewTreeConnectRes() (TreeConnectResponse, error) {
	return TreeConnectResponse{}, nil
}

func (s *SessionC) TreeConnect(name string) error {
	s.Debug("Sending TreeConnect request ["+name+"]", nil)

	req, err := NewTreeConnectReq(s, name)
	var res TreeConnectResponse
	if err = s.RPC(req, &res); err != nil {
		return err
	}

	if res.Header.Status != StatusOk {
		return errors.New("Failed to connect to tree: " + StatusMap[res.Header.Status])
	}
	s.trees[name] = res.Header.TreeID

	s.Debug("Completed TreeConnect ["+name+"]", nil)
	return nil
}

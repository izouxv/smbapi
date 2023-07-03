package smb

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"strings"
	"sync/atomic"

	"github/izouxv/smbapi/smb/encoder"
	"github/izouxv/smbapi/util"

	"github.com/izouxv/logx"
	"golang.org/x/net/webdav"
)

func init() {
	commandRequestMap[CommandCreate] = func() DataI {
		return &CreateRequest{
			// CreateContexts: &SMB2_CREATE_CONTEXT{},
		}
	}
}

// handle_Create

type CreateDisposition uint32

const (
	FILE_SUPERSEDE    CreateDisposition = 0x00000000 //If the file already exists, supersede it. Otherwise, create the file. This value SHOULD NOT be used for a printer object.<30>
	FILE_OPEN         CreateDisposition = 0x00000001 //If the file already exists, return success; otherwise, fail the operation. MUST NOT be used for a printer object.
	FILE_CREATE       CreateDisposition = 0x00000002 //If the file already exists, fail the operation; otherwise, create the file.
	FILE_OPEN_IF      CreateDisposition = 0x00000003 //Open the file if it already exists; otherwise, create the file. This value SHOULD NOT	be used for a printer object.<31>
	FILE_OVERWRITE    CreateDisposition = 0x00000004 //Overwrite the file if it already exists; otherwise, fail the operation. MUST NOT be	used for a printer object.
	FILE_OVERWRITE_IF CreateDisposition = 0x00000005 //Overwrite the file if it already exists; otherwise, create the file. This value SHOULD	NOT be used for a printer object.<32>
)

var _ encoder.BinaryMarshallable = CreateDisposition(0)

func (c CreateDisposition) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c CreateDisposition) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type ShareAccess uint32

const (
	FILE_SHARE_READ   ShareAccess = 0x00000001
	FILE_SHARE_WRITE  ShareAccess = 0x00000002
	FILE_SHARE_DELETE ShareAccess = 0x00000004
)

var _ encoder.BinaryMarshallable = FileAttributes(0)

func (c ShareAccess) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c ShareAccess) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type CreateOptions uint32

const (
	FILE_DIRECTORY_FILE            CreateOptions = 0x00000001
	FILE_WRITE_THROUGH             CreateOptions = 0x00000002
	FILE_SEQUENTIAL_ONLY           CreateOptions = 0x00000004
	FILE_NO_INTERMEDIATE_BUFFERING CreateOptions = 0x00000008

	FILE_SYNCHRONOUS_IO_ALERT    CreateOptions = 0x00000010
	FILE_SYNCHRONOUS_IO_NONALERT CreateOptions = 0x00000020
	FILE_NON_DIRECTORY_FILE      CreateOptions = 0x00000040

	FILE_COMPLETE_IF_OPLOCKED CreateOptions = 0x00000100
	FILE_NO_EA_KNOWLEDGE      CreateOptions = 0x00000200
	FILE_OPEN_REMOTE_INSTANCE CreateOptions = 0x00000400
	FILE_RANDOM_ACCESS        CreateOptions = 0x00000800

	FILE_DELETE_ON_CLOSE        CreateOptions = 0x00001000
	FILE_OPEN_BY_FILE_ID        CreateOptions = 0x00002000
	FILE_OPEN_FOR_BACKUP_INTENT CreateOptions = 0x00004000
	FILE_NO_COMPRESSION         CreateOptions = 0x00008000

	FILE_OPEN_REQUIRING_OPLOCK CreateOptions = 0x00010000
	FILE_DISALLOW_EXCLUSIVE    CreateOptions = 0x00020000

	FILE_RESERVE_OPFILTER          CreateOptions = 0x00100000
	FILE_OPEN_REPARSE_POINT        CreateOptions = 0x00200000
	FILE_OPEN_NO_RECALL            CreateOptions = 0x00400000
	FILE_OPEN_FOR_FREE_SPACE_QUERY CreateOptions = 0x00800000
)

var _ encoder.BinaryMarshallable = CreateOptions(0)

func (c CreateOptions) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c CreateOptions) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type FileAttributes uint32

const (
	//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/ca28ec38-f155-4768-81d6-4bfeb8586fc9

	FILE_ATTRIBUTE_READONLY  FileAttributes = 0x00000001 //A file or directory that is read-only. For a file, applications can read the file but cannot write to it or delete it. For a directory, applications cannot delete it, but applications can create and delete files from that directory.
	FILE_ATTRIBUTE_HIDDEN    FileAttributes = 0x00000002 // A file or directory that is hidden. Files and directories marked with this attribute do not appear in an ordinary directory listing.
	FILE_ATTRIBUTE_SYSTEM    FileAttributes = 0x00000004 // A file or directory that the operating system uses a part of or uses exclusively.
	FILE_ATTRIBUTE_DIRECTORY FileAttributes = 0x00000010 // This item is a directory.
	FILE_ATTRIBUTE_ARCHIVE   FileAttributes = 0x00000020 // A file or directory that requires to be archived. Applications use this attribute to mark files for backup or removal.
	FILE_ATTRIBUTE_NORMAL    FileAttributes = 0x00000080 // A file that does not have other attributes set. This flag is used to clear all other flags by specifying it with no other flags set.
	//This flag MUST be ignored if other flags are set.<161>
	FILE_ATTRIBUTE_TEMPORARY             FileAttributes = 0x00000100 // A file that is being used for temporary storage. The operating system can choose to store this file's data in memory rather than on mass storage, writing the data to mass storage only if data remains in the file when the file is closed.
	FILE_ATTRIBUTE_SPARSE_FILE           FileAttributes = 0x00000200 // A file that is a sparse file.
	FILE_ATTRIBUTE_REPARSE_POINT         FileAttributes = 0x00000400 // A file or directory that has an associated reparse point.
	FILE_ATTRIBUTE_COMPRESSED            FileAttributes = 0x00000800 // A file or directory that is compressed. For a file, all of the data in the file is compressed. For a directory, compression is the default for newly created files and subdirectories.
	FILE_ATTRIBUTE_OFFLINE               FileAttributes = 0x00001000 // The data in this file is not available immediately. This attribute indicates that the file data is physically moved to offline storage. This attribute is used by Remote Storage, which is hierarchical storage management software.
	FILE_ATTRIBUTE_NOT_CONTENT_INDEXED   FileAttributes = 0x00002000 // A file or directory that is not indexed by the content indexing service.
	FILE_ATTRIBUTE_ENCRYPTED             FileAttributes = 0x00004000 // A file or directory that is encrypted. For a file, all data streams in the file are encrypted. For a directory, encryption is the default for newly created files and subdirectories.
	FILE_ATTRIBUTE_INTEGRITY_STREAM      FileAttributes = 0x00008000 // A file or directory that is configured with integrity support. For a file, all data streams in the file have integrity support. For a directory, integrity support is the default for newly created files and subdirectories, unless the caller specifies otherwise.<162>
	FILE_ATTRIBUTE_NO_SCRUB_DATA         FileAttributes = 0x00020000 // A file or directory that is configured to be excluded from the data integrity scan. For a directory configured with FILE_ATTRIBUTE_NO_SCRUB_DATA, the default for newly created files and subdirectories is to inherit the FILE_ATTRIBUTE_NO_SCRUB_DATA attribute.<163>
	FILE_ATTRIBUTE_RECALL_ON_OPEN        FileAttributes = 0x00040000 // This attribute appears only in directory enumeration classes (FILE_DIRECTORY_INFORMATION, FILE_BOTH_DIR_INFORMATION, etc.). When this attribute is set, it means that the file or directory has no physical representation on the local system; the item is virtual. Opening the item will be more expensive than usual because it will cause at least some of the file or directory content to be fetched from a remote store. This attribute can only be set by kernel-mode components. This attribute is for use with hierarchical storage management software.<164>
	FILE_ATTRIBUTE_PINNED                FileAttributes = 0x00080000 // This attribute indicates user intent that the file or directory should be kept fully present locally even when not being actively accessed. This attribute is for use with hierarchical storage management software.<165>
	FILE_ATTRIBUTE_UNPINNED              FileAttributes = 0x00100000 // This attribute indicates that the file or directory should not be kept fully present locally except when being actively accessed. This attribute is for use with hierarchical storage management software.<166>
	FILE_ATTRIBUTE_RECALL_ON_DATA_ACCESS FileAttributes = 0x00400000
)

var _ encoder.BinaryMarshallable = FileAttributes(0)

func (c FileAttributes) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c FileAttributes) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type CreateRequest struct {
	Header

	StructureSize      uint16
	SecurityFlags      uint8             //1字节，保留字段，不得使用
	OpLock             uint8             //1字节，对应文档RequestedOplockLevel字段
	ImpersonationLevel uint32            //4字节，模拟等级
	CreateFlags        []byte            `smb:"fixed:8"` //8字节，保留字段，不得使用
	Reserved           []byte            `smb:"fixed:8"`
	AccessMask         AccessMask        //DesiredAccess    //4字节，访问权限
	FileAttributes     FileAttributes    //4字节，文件属性
	ShareAccess        ShareAccess       //ShareAccess//4字节，共享模式
	CreateDisposition  CreateDisposition //CreateDispositionStat
	CreateOptions      CreateOptions
	NameOffset         uint16 `smb:"offset:Filename"`
	NameLength         uint16 `smb:"len:Filename"`
	// Filename             []byte `smb:"unicode"`

	CreateContextsOffset uint32 `smb:"offset:CreateContexts"`
	CreateContextsLength uint32 `smb:"len:CreateContexts"`

	// BlankByte []byte `smb:"fixed:8"` //blank space

	// Filename []byte
	Filename       []byte // `smb:"unicode"`
	CreateContexts []byte
	// CreateContexts *SMB2_CREATE_CONTEXT // []byte `smb:"unicode"`
}

type CreateAction uint32

const (
	FILE_SUPERSEDED  CreateAction = 0x00000000
	FILE_OPENED      CreateAction = 0x00000001
	FILE_CREATED     CreateAction = 0x00000002
	FILE_OVERWRITTEN CreateAction = 0x00000003
)

func (c CreateAction) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c CreateAction) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type CreateResponse struct {
	Header

	StructureSize uint16
	Oplock        uint8 //1字节，对应文档RequestedOplockLevel字段
	ResponseFlags uint8
	CreateAction  CreateAction
	// CreationTime   []byte `smb:"fixed:8"` //8字节，创建时间
	// LastAccessTime []byte `smb:"fixed:8"` //8字节
	// LastWriteTime  []byte `smb:"fixed:8"` //8字节
	// LastChangeTime []byte `smb:"fixed:8"` //8字节
	// AllocationSize []byte `smb:"fixed:8"` //8字节，文件大小
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndOfFile      uint64

	FileAttributes FileAttributes
	Reserved2      []byte `smb:"fixed:4"`
	FileId         GUID   //   []byte `smb:"fixed:16"` //16字节，文件句柄

	CreateContextsOffset uint32 `smb:"offset:CreateContexts"`
	CreateContextsLength uint32 `smb:"len:CreateContexts"`
	CreateContexts       []byte
}

type GUID [16]byte

var (
	NilGUID  GUID = [16]byte{}
	LastGUID GUID
)

func init() {
	copy(LastGUID[:], bytes.Repeat([]byte{255}, 16)[:16])
	copy(NilGUID[:], bytes.Repeat([]byte{0}, 16)[:16])
}

func (g GUID) treeId() uint32 {
	return binary.LittleEndian.Uint32(g[:])
}
func (g GUID) IsSvrSvc(s *SessionS) bool {
	return bytes.Equal(s.srvsvc[:], g[:])
}
func (g GUID) IsEqual(b GUID) bool {
	return bytes.Equal(b[:], g[:])
}

func makeGUID(treeId uint32, fid uint64) GUID {
	var guid GUID
	binary.LittleEndian.PutUint64(guid[:], uint64(treeId))
	binary.LittleEndian.PutUint64(guid[8:], fid)
	return guid
}

var xx [16]byte
var _ encoder.BinaryMarshallable = GUID(xx)

func (c GUID) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return c[:], nil
}
func (c GUID) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	var cc GUID
	copy(cc[:], data[:16])
	meta.CurrOffset += 16
	return cc, nil
}

const k_srvsvc = "srvsvc"

func (data *CreateRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	Filename, err := encoder.FromUnicode(data.Filename)
	if err != nil {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}

	var createContextsResp []byte = nil
	if len(data.CreateContexts) > 0 {
		createContextsRequest := &SMB2_CREATE_CONTEXT_REQUEST{}
		encoder.Unmarshal(data.CreateContexts, createContextsRequest)

		createContextsResp = createContextsRequest.Action(func(ttt SMB2_CREATE_CONTEXT_RESPONSE_TYPE, request interface{}) (interface{}, error) {
			switch ttt {
			case SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE_TAG:
				return &SMB2_CREATE_QUERY_MAXIMAL_ACCESS_RESPONSE{MaximalAccess: AllAccessMask}, nil
			case SMB2_APPL_CREATE_CONTENT_TAG:
				return nil, fmt.Errorf("NA")
				return &SMB2_APPL_CREATE_CONTENT_TAG_RESPONSE{}, nil
			default:
				return nil, fmt.Errorf("NA")
			}
		})
	}

	Filename = strings.Replace(Filename, "\\", "/", -1)

	var createAction = FILE_SUPERSEDED

	openFlags := 0
	switch data.CreateDisposition {
	case FILE_SUPERSEDE:
		createAction = FILE_SUPERSEDED
		openFlags = os.O_TRUNC | os.O_CREATE | os.O_RDWR
	case FILE_OPEN:
		createAction = FILE_OPENED
	case FILE_CREATE:
		createAction = FILE_CREATED
		openFlags = os.O_TRUNC | os.O_CREATE | os.O_RDWR //os.O_EXCL | os.O_RDWR
	case FILE_OPEN_IF:
		createAction = FILE_CREATED
		openFlags = os.O_CREATE
	case FILE_OVERWRITE:
		createAction = FILE_OVERWRITTEN
		openFlags = os.O_TRUNC
	case FILE_OVERWRITE_IF:
		createAction = FILE_OVERWRITTEN
		openFlags = os.O_TRUNC | os.O_CREATE | os.O_RDWR
	default:
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}

	if true {
		if openFlags&os.O_TRUNC > 0 {
			absPath := ctx.session.GetAbsPath(Filename)
			if util.FileExist(absPath) {
				logx.Printf("truncate")
			}
		}
	}

	if data.AccessMask&(FILE_WRITE_DATA|GENERIC_ALL|GENERIC_WRITE) != 0 {
		openFlags |= os.O_RDWR
	} else if openFlags&os.O_RDWR == 0 {
		openFlags |= os.O_RDONLY
	}
	fid := atomic.AddUint64(&ctx.session.fileNum, 1)
	guid := makeGUID(data.TreeID, fid)

	if Filename == k_srvsvc {
		ctx.session.srvsvc = guid

		absPath := ctx.session.GetAbsPath(Filename)
		if !util.FileExist(absPath) {
			f, err := os.Create(absPath)
			if err == nil {
				f.Close()
			}
		}
	}

	var webfile webdav.File
	isDir := data.FileAttributes&FILE_ATTRIBUTE_DIRECTORY > 0
	if data.CreateDisposition == FILE_CREATE {
		// openFlags = (os.O_RDWR | os.O_CREATE | os.O_TRUNC)
		if isDir {
			absPath := ctx.session.GetAbsPath(Filename)
			err = ctx.Handle().FileSystem.Mkdir(context.Background(), absPath, 07777)
			if err != nil {
				return ERR(data.Header, STATUS_UNSUCCESSFUL)
			}
			openFlags = 0
		} else {
		}
	}

	ok, path, xattr := IsXAttr(Filename)
	if ok { //处理xattr数据
		// return ERR(data.Header, STATUS_NOT_IMPLEMENTED)
		// } else if (data.AccessMask&FILE_READ_ATTRIBUTES > 0 || data.AccessMask&DELETE > 0) && ok {
		absPath := ctx.session.GetAbsPath(path)
		absPathAttr := ctx.session.GetAbsPath(Filename)
		attrTag := XATTR_Key(xattr)
		// 	// com.apple.lastuseddate#PS
		// 	// com.apple.metadata _kMDItemUserTag s
		// 	// com.apple.metadata _kMDItemFavoriteRank
		openFlags = 0 // os.O_TRUNC会重置文件，所以需要把它换成0
		// webfile, err = ctx.Handle().FileSystem.OpenFile(context.Background(), absPath, openFlags, 0666)
		webfile = &webdavFile{filename: absPath, filenameAttr: absPathAttr, webdavType: attrTag}
		_, err = webfile.Stat()
		if err != nil {
			webfile.Close()
			return ERR(data.Header, STATUS_OBJECT_NAME_NOT_FOUND)
		}
	} else {
		absPath := ctx.session.GetAbsPath(Filename)
		webfile, err = ctx.Handle().FileSystem.OpenFile(context.Background(), absPath, openFlags, 0666)
		if err != nil {
			return ERR(data.Header, STATUS_OBJECT_NAME_NOT_FOUND)
		}
	}

	if os.IsNotExist(err) {
		return ERR(data.Header, STATUS_OBJECT_NAME_NOT_FOUND)
	}
	if err != nil {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}

	ctx.session.openedFiles[guid] = webfile

	fi, err := webfile.Stat()
	if err != nil {
		return ERR(data.Header, STATUS_UNSUCCESSFUL)
	}

	data.Header.Status = StatusOk
	resp := CreateResponse{
		Header:        data.Header,
		StructureSize: 89,
		FileId:        guid,
		CreateAction:  createAction,
	}

	if fi.IsDir() {
		resp.FileAttributes |= FILE_ATTRIBUTE_DIRECTORY
	} else {
		resp.FileAttributes |= FILE_ATTRIBUTE_NORMAL
		resp.EndOfFile = uint64(fi.Size())
		resp.AllocationSize = uint64(fi.Size())
	}
	mtime := timeToFiletime(fi.ModTime())
	resp.CreationTime = mtime
	resp.LastWriteTime = mtime
	resp.ChangeTime = mtime
	resp.LastAccessTime = 0
	ctx.latestFileId = guid
	resp.CreateContexts = createContextsResp

	return resp, nil

}

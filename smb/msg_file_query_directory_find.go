package smb

import (
	"bytes"
	"encoding/binary"
	"io/fs"
	"path/filepath"
	"sync/atomic"

	"github/izouxv/smbapi/smb/encoder"
)

func init() {
	commandRequestMap[CommandFind] = func() DataI {
		return &QueryDirectoryRequest{}
	}
}

type FindFlags uint8

const (
	RestartScans FindFlags = 0x0001
)

func (c FindFlags) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c FindFlags) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type QueryDirectoryRequest struct {
	Header
	StructureSize  uint16
	InfoLevel      FileInformationClass
	FindFlags      FindFlags //1: restart scan
	FileIndex      uint32
	FileId         GUID
	FileNameOffset uint16 `smb:"offset:FileName"`
	FileNameLength uint16 `smb:"len:FileName"`
	// BlobOffset         uint16 `smb:"offset:Blob"`
	// BlobLength         uint16 `smb:"len:Blob"`
	OutputBufferLength uint32
	// Blob               []byte //unicode
	FileName []byte //unicode

}

type QueryDirectoryResponse struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16 `smb:"offset:OutputBuffer"`
	OutputBufferLength uint32 `smb:"len:OutputBuffer"`
	OutputBuffer       []byte
}

var KFILEID = uint64(0)

func (data *QueryDirectoryRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE

	fileid := ctx.FileID(data.FileId)
	webfile, ok := ctx.session.openedFiles[fileid]
	if !ok {
		return ERR(data.Header, STATUS_FILE_CLOSED)
	}

	getFileIdBothDirInfo := func(fi fs.FileInfo) *FileIdBothDirectoryInfo {
		mtime := timeToFiletime(fi.ModTime())
		filename := filepath.Base(fi.Name())
		nameByte := encoder.ToUnicode(filename)
		var fa FileAttributes
		size := uint32(fi.Size())
		var AllocationSize, EndOfFile uint64
		if fi.IsDir() {
			fa |= FILE_ATTRIBUTE_DIRECTORY
			// logx.Printf("fa if: %v", fa)
			//TODO
			size = 0x011111111
		} else {
			// fa |= FILE_ATTRIBUTE_ARCHIVE
			fa |= FILE_ATTRIBUTE_NORMAL
			AllocationSize = uint64(fi.Size()) //磁盘大小, 会有碎片, 比endoffile大一点
			EndOfFile = uint64(fi.Size())      //文件大小
			if size == 0 {
				size = 0x011111111
			}
		}

		// logx.Printf("fa: %v", fa)
		fid := atomic.AddUint64(&KFILEID, 1)
		return &FileIdBothDirectoryInfo{
			CreateTime:     mtime,
			LastAccessTime: mtime,
			LastWriteTime:  mtime,
			LastChangeTime: mtime,
			FileName:       nameByte,
			AllocationSize: AllocationSize, //磁盘大小, 会有碎片, 比endoffile大一点
			EndOfFile:      EndOfFile,      //文件大小
			FileAttributes: fa,
			FileId:         fid,
			EASize:         size,
		}
	}

	FileName, err := encoder.FromUnicode(data.FileName)
	if err != nil {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
		return nil, err
	}

	var OutputBuffer []byte
	if data.FindFlags == 0 {
		return ERR(data.Header, STATUS_NO_MORE_FILES)
	}

	// data.FindFlags == 0   RestartScans
	switch data.InfoLevel {
	case FileIdBothDirectoryInformation:
		switch FileName {
		case "*":
			fis, err := webfile.Readdir(0)
			if err != nil {
				return nil, err
			}
			var items [][]byte

			selfFI, err := webfile.Stat()
			if err != nil {
				return nil, err
			}
			fis = append(fis, &fileInfoX{FileInfo: selfFI, name: "."})
			fis = append(fis, &fileInfoX{FileInfo: selfFI, name: ".."})

			for _, fi := range fis {
				info := getFileIdBothDirInfo(fi)
				itemBuf, err := encoder.Marshal(info)
				if err != nil {
					//如果有错误, 就继续. 这个看以后是否修改.
					continue
				}
				items = append(items, itemBuf)
			}
			if true {
				for i := 0; i < len(items); i++ {
					//需要设置每个包的大小.用来分割包.最后一个包不用.
					if i != len(items)-1 {
						line := items[i]
						binary.LittleEndian.PutUint32(line, uint32(len(line)))
					}
				}
				OutputBuffer = bytes.Join(items, []byte{})
			}
			data.Header.Status = StatusOk
			if len(items) == 0 {
				return ERR(data.Header, STATUS_NO_MORE_FILES)
			}
		default:
			fis, err := webfile.Readdir(0)
			if err != nil {
				return nil, err
			}
			var fi fs.FileInfo
			for _, item := range fis {
				if item.Name() == FileName {
					fi = item
					break
				}
			}
			if fi != nil {
				info := getFileIdBothDirInfo(fi)
				OutputBuffer, err = encoder.Marshal(info)
			}
			data.Header.Status = StatusOk
			if len(OutputBuffer) == 0 {
				return ERR(data.Header, STATUS_NO_SUCK_FILE)
			}
		}
	}

	if err != nil {
		return nil, err
	}

	resp := QueryDirectoryResponse{
		Header:        data.Header,
		StructureSize: 0x0009,
		OutputBuffer:  OutputBuffer,
		// OutputBufferOffset: 0x0048,
		// OutputBufferLength: uint32(len(OutputBuffer)),
	}
	return &resp, nil
}

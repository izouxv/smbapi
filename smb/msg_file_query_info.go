package smb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github/izouxv/smbapi/smb/encoder"
)

func init() {
	commandRequestMap[CommandQueryInfo] = func() DataI {
		return &QueryInfoRequest{}
	}
}

type QueryInfoRequest struct {
	Header
	StructureSize         uint16
	Class                 InfoType //Class
	InfoLevel             uint8    //FileSystemInformationClass or FileInformationClass
	OutputBufferLength    uint32   //max response size
	InputBufferOffset     uint16   `smb:"offset:InputBuffer"`
	Reserved              uint16
	InputBufferLength     uint32 `smb:"len:InputBuffer"`
	AdditionalInformation uint32
	Flags                 uint32
	FileId                GUID
	InputBuffer           []byte
}

type QueryInfoResponse struct {
	Header
	StructureSize      uint16
	OutputBufferOffset uint16 `smb:"offset:OutputBuffer"`
	OutputBufferLength uint32 `smb:"len:OutputBuffer"`
	OutputBuffer       []byte
}

func (data *QueryInfoRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE

	fileid := ctx.FileID(data.FileId)
	webfile, ok := ctx.session.openedFiles[fileid]
	if !ok {
		return ERR(data.Header, STATUS_FILE_CLOSED)
	}

	var OutputBuffer []byte
	var err error

	switch data.Class {
	case SMB2_0_INFO_FILE:
		switch FileInformationClass(data.InfoLevel) {
		case FileStreamInformation:
			ff := webfile.(*os.File)

			var infos [][]byte
			if true {
				fi, err := ff.Stat()
				if err != nil {
					return nil, err
				}
				datakey := "::$DATA"
				name := encoder.ToUnicode(datakey)
				info := &FileStreamInformationX{
					StreamSize:           uint64(fi.Size()),
					StreamAllocationSize: uint64(fi.Size()),
					StreamName:           name,
				}
				infobuf, err := encoder.Marshal(info)
				if err != nil {
					panic(-1)
				}

				infos = append(infos, Duiqi4Byte(infobuf))
			}

			keys, err := XAttrGetKeys(ff.Name())
			if err != nil {
				return nil, fmt.Errorf("err")
			}

			for _, key := range keys {
				datakey := fmt.Sprintf(":%v:$DATA", key)
				name := encoder.ToUnicode(datakey)

				data, err := XAttrGet(ff.Name(), key)
				if err != nil {
					continue
				}
				info := &FileStreamInformationX{
					StreamSize:           uint64(len(data)),
					StreamAllocationSize: uint64(len(data)),
					StreamName:           name,
				}
				infobuf, err := encoder.Marshal(info)
				if err != nil {
					continue
				}
				infos = append(infos, Duiqi4Byte(infobuf))
			}

			//write offset
			for i, info := range infos {
				if i != len(infos)-1 {
					binary.LittleEndian.PutUint32(info, uint32(len(info)))
				}
			}

			OutputBuffer = bytes.Join(infos, []byte{})

		case FileAllInformation:
			fi, _ := webfile.Stat()
			fname := filepath.Base(fi.Name())
			IsDirectory := 0
			fid := uint64(0)
			FileAttributes := uint32(0x000020)
			if fi.IsDir() {
				IsDirectory = 1
				FileAttributes = uint32(0x000010)
			} else {
				fid = atomic.AddUint64(&KFILEID, 1)
			}
			mtime := timeToFiletime(fi.ModTime())

			info := SMB2_FILE_ALL_INFO{
				CreateTime:     mtime,
				LastAccessTime: mtime,
				LastWriteTime:  mtime,
				LastChangeTime: mtime,
				AccessMask:     AllAccessMask,
				NumberOfLinks:  18,
				FileID:         fid,
				FileAttributes: FileAttributes,
				IsDirectory:    uint8(IsDirectory),
				FileName:       encoder.ToUnicode(fname),
			}

			OutputBuffer, err = encoder.Marshal(info)
			if err != nil {
				return ERR(data.Header, STATUS_INVALID_PARAMETER)
			}

			// logx.Printf("FileAllInformation: \n%v", hex.Dump(OutputBuffer))
		}
	case SMB2_0_INFO_FILESYSTEM:
		switch FileSystemInformationClass(data.InfoLevel) {
		case FileFsAttributeInformation:
			//TODO 获取FSInfo
			ntfs := encoder.ToUnicode("NTFS")
			info := FileFsAttributeInformationX{
				FSAttributes:  0x10400c6,
				MaxNameLength: 256,
				FSName:        ntfs,
			}
			OutputBuffer, err = encoder.Marshal(info)
			if err != nil {
				return ERR(data.Header, STATUS_INVALID_PARAMETER)
			}
		case FileFsSizeInformation:
			//TODO 计算磁盘剩余大小.
			info := FileFsSizeInformationX{
				AllocationSize: 0xfffffff,
				FreeUnits:      0xffffff,
				SectorsUnit:    1,
				BytesPerSector: 4096,
			}
			OutputBuffer, err = encoder.Marshal(info)
			if err != nil {
				return ERR(data.Header, STATUS_INVALID_PARAMETER)
			}
		}
	}

	data.Header.Status = StatusOk
	resp := QueryInfoResponse{
		Header:        data.Header,
		StructureSize: 9,
		OutputBuffer:  OutputBuffer,
	}
	return &resp, nil
}

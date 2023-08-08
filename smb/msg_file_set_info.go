package smb

import (
	"context"
	"os"
	"strings"

	"github/izouxv/smbapi/smb/encoder"

	"github.com/izouxv/logx"
)

func init() {
	commandRequestMap[CommandSetInfo] = func() DataI {
		return &SetInfoRequest{}
	}
}

type SetInfoRequest struct {
	Header
	StructureSize         uint16
	InfoType              InfoType
	FileInfoClass         FileInformationClass //https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1
	BufferLength          uint32               `smb:"len:Buffer"`
	BufferOffset          uint16               `smb:"offset:Buffer"`
	Reserved              uint16
	AdditionalInformation uint32
	FileId                GUID

	Buffer []byte
}

type SetInfoResponse struct {
	Header
	StructureSize uint16
}

func (data *SetInfoRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE

	// if !data.FileId.IsEqual(LastGUID) {
	// 	panic(-1)
	// }

	if data.InfoType != SMB2_0_INFO_FILE {
		logx.Warnf("data.InfoType NotSupport: %v", data.InfoType)
		return ERR(data.Header, STATUS_NOT_SUPPORTED)
	}
	if len(data.Buffer) > 0 {
		fileid := ctx.FileID(data.FileId)
		webfile, ok := ctx.session.openedFiles[fileid]
		if !ok {
			return ERR(data.Header, STATUS_FILE_CLOSED)
		}

		switch data.FileInfoClass {
		case FileBasicInformation:
			resp := &FileBasicInformationX{}
			if err := encoder.Unmarshal(data.Buffer, resp); err == nil {
				ctx.closeAction = func() {
				}
			}
		case FileDispositionInformation:
			resp := &FileDispositionInformationX{}
			if err := encoder.Unmarshal(data.Buffer, resp); err == nil {
				if file, ok := webfile.(*os.File); ok {
					//删除文件.
					if resp.DeletePending == 1 {
						ctx.closeAction = func() {
							FilePath := file.Name()
							ctx.Handle().FileSystem.RemoveAll(context.Background(), FilePath)
						}
					}
				}
				if file, ok := webfile.(*webdavFile); ok {
					//删除文件xattr属性
					ctx.closeAction = func() {
						file.XAttrDelete()
					}
				}
			}

		case FileRenameInformation:

			resp := &FileRenameInformationX{}
			if err := encoder.Unmarshal(data.Buffer, resp); err == nil {
				if file, ok := webfile.(*os.File); ok {
					FilePath := file.Name()
					// ctx.closeAction = func() {
					filename, err := encoder.FromUnicode(resp.FileName)
					if err != nil {
						return ERR(data.Header, STATUS_UNSUCCESSFUL)
					}
					filename = strings.ReplaceAll(filename, "\\", "/")
					NewFilePath := ctx.session.GetAbsPath(filename)
					if resp.ReplaceIfExists == 0x01 {
						err = ctx.Handle().FileSystem.RemoveAll(context.Background(), NewFilePath)
						if err != nil {
							return ERR(data.Header, STATUS_UNSUCCESSFUL)
						}
					}
					err = ctx.Handle().FileSystem.Rename(context.Background(), FilePath, NewFilePath)
					if err != nil {
						return ERR(data.Header, STATUS_UNSUCCESSFUL)
					}
					// }
				}
			}
		default:
			logx.Warnf("data.FileInfoClass NotSupport: %v", data.FileInfoClass)
			return ERR(data.Header, STATUS_NOT_SUPPORTED)
		}
	}

	data.Header.Status = StatusOk
	resp := SetInfoResponse{
		Header:        data.Header,
		StructureSize: 2,
	}
	return &resp, nil
}

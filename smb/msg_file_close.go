package smb

func init() {
	commandRequestMap[CommandClose] = func() DataI {
		return &CloseRequest{}
	}
}

//CommandClose

type CloseRequest struct {
	Header
	StructureSize uint16
	Flags         uint16
	Reserved      uint32
	FileId        GUID
}

const SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB = 0x0001

type CloseResponse struct {
	Header
	StructureSize  uint16
	Flags          uint16
	Reserved       uint32
	CreationTime   uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	ChangeTime     uint64
	AllocationSize uint64
	EndofFile      uint64
	FileAttributes uint32
}

func (data *CloseRequest) ServerAction(ctx *DataCtx) (interface{}, error) {
	data.Header.Flags = SMB2_FLAGS_RESPONSE
	if data.StructureSize != 24 {
		return ERR(data.Header, STATUS_INVALID_PARAMETER)
	}

	fileid := ctx.FileID(data.FileId)
	webfile, ok := ctx.session.openedFiles[fileid]
	if !ok {
		return ERR(data.Header, STATUS_FILE_CLOSED)
	}

	data.Header.Status = StatusOk
	resp := &CloseResponse{
		Header:        data.Header,
		StructureSize: 0x003c,
	}

	if data.Flags&SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB == SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB {
		fi, err := webfile.Stat()
		if err == nil {
			mtime := timeToFiletime(fi.ModTime())
			resp.CreationTime = mtime
			resp.LastWriteTime = mtime
			resp.ChangeTime = mtime
			resp.LastAccessTime = 0 // timeToFiletime(statAccessTime(fi))

			resp.Flags = 1
		}
	}

	delete(ctx.session.openedFiles, fileid)
	if webfile != nil {
		webfile.Close()
	}
	if ctx.closeAction != nil {
		ctx.closeAction()
		ctx.closeAction = nil
	}
	ctx.latestFileId = NilGUID

	return resp, nil

}

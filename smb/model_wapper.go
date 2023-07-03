package smb

import (
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/net/webdav"
)

type fileInfoX struct {
	fs.FileInfo
	name string
	size int64
}

func (f *fileInfoX) Name() string {
	return f.name
}
func (f *fileInfoX) Size() int64 {
	if f.size == 0 {
		return f.FileInfo.Size()
	}
	return f.size
}

var _ webdav.File = (*webdavFile)(nil)

type webdavFile struct {
	// webdav.File
	filename     string
	filenameAttr string
	webdavType   XATTR_Key
}

func (w *webdavFile) XAttrDelete() (err error) {
	// file := w.File.(*os.File)
	// filename := file.Name()
	return XAttrDel(w.filename, string(w.webdavType))
}
func (w *webdavFile) Write(p []byte) (n int, err error) {
	// file := w.File.(*os.File)
	// filename := file.Name()
	err = XAttrSet(w.filename, string(w.webdavType), p)
	if err != nil {
		return 0, err
	}
	return n, nil
}
func (w *webdavFile) Close() error {
	return nil
}
func (w *webdavFile) Read(p []byte) (n int, err error) {
	if true {
		// file := w.File.(*os.File)
		// filename := file.Name()
		v, err := XAttrGet(w.filename, string(w.webdavType))
		if err != nil {
			return 0, err
		}
		n := copy(p, v)
		return n, nil
	}

	// switch w.webdavType {
	// case XATTR_PS_EA_NAME,
	// 	XATTR_KMD_ITEM_USER_TAGS_EA_NAME,
	// 	XATTR_FINDER_INFO_EA_NAME:
	// 	file := w.File.(*os.File)
	// 	filename := file.Name()
	// 	v, err := XAttrGet(filename, string(w.webdavType))
	// 	if err != nil {
	// 		return 0, err
	// 	}
	// 	n := copy(p, v)
	// 	return n, nil
	// default:
	// }
	return -1, io.EOF
}
func (w *webdavFile) Seek(offset int64, whence int) (int64, error) {
	return 0, nil
}
func (w *webdavFile) Readdir(count int) ([]fs.FileInfo, error) {
	return nil, nil
}
func (w *webdavFile) Stat() (fs.FileInfo, error) {
	return &fileInfoX{FileInfo: &Stat{name: filepath.Base(w.filenameAttr)}, size: int64(16)}, nil
	// fi, err := w.File.Stat()
	// if err != nil {
	// 	return nil, err
	// }

	// data := make([]byte, 1024)
	// size, err := w.Read(data)
	// if err != nil {
	// 	return nil, err
	// }
	// return &fileInfoX{FileInfo: fi, size: int64(size)}, nil
}

type Stat struct {
	// osStat os.FileInfo
	name string
}

func (st Stat) Name() string       { return st.name }
func (st Stat) Size() int64        { return 16 }
func (st Stat) ModTime() time.Time { return time.Now() }
func (st Stat) Mode() os.FileMode  { return 0 }
func (st Stat) IsDir() bool        { return false }
func (st Stat) Sys() any           { return nil }

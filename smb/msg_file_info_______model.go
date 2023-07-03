package smb

import "github/izouxv/smbapi/smb/encoder"

/// [MS-FSCC] 2.4 - File Information Classes

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1

type FileInformationClass uint8

const (
	// FileDirectoryInformation     FileInformationClass = 0x01 // Uses: Query
	// FileFullDirectoryInformation FileInformationClass = 0x02 // Uses: Query
	// FileBothDirectoryInformation FileInformationClass = 0x03 // Uses: Query
	FileBasicInformation FileInformationClass = 0x04 // Uses: Query, Set
	// FileStandardInformation        FileInformationClass = 0x05 // Uses: Query
	// FileInternalInformation        FileInformationClass = 0x06 // Uses: Query
	// FileEaInformation              FileInformationClass = 0x07 // Uses: Query
	// FileAccessInformation          FileInformationClass = 0x08 // Uses: Query
	// FileNameInformation            FileInformationClass = 0x09 // Uses: LOCAL
	FileRenameInformation FileInformationClass = 0x0A // Uses: Set
	// FileLinkInformation            FileInformationClass = 0x0B // Uses: Set
	// FileNamesInformation FileInformationClass = 0x0C // Uses: Query
	FileDispositionInformation FileInformationClass = 0x0D // Uses: Set
	// FilePositionInformation        FileInformationClass = 0x0E // Uses: Query, Set
	// FileFullEaInformation          FileInformationClass = 0x0F // Uses: Query, Set
	// FileModeInformation            FileInformationClass = 0x10 // Uses: Query, Set
	// FileAlignmentInformation       FileInformationClass = 0x11 // Uses: Query
	FileAllInformation FileInformationClass = 0x12 // Uses: Query
	// FileAllocationInformation      FileInformationClass = 0x13 // Uses: Set
	// FileEndOfFileInformation       FileInformationClass = 0x14 // Uses: Set
	// FileAlternateNameInformation   FileInformationClass = 0x15 // Uses: Query
	FileStreamInformation FileInformationClass = 0x16 // Uses: Query
	// FilePipeInformation            FileInformationClass = 0x17 // Uses: Query, Set
	// FilePipeLocalInformation       FileInformationClass = 0x18 // Uses: Query
	// FilePipeRemoteInformation      FileInformationClass = 0x19 // Uses: Query
	// FileCompressionInformation     FileInformationClass = 0x1C // Uses: Query
	// FileNetworkOpenInformation     FileInformationClass = 0x22 // Uses: Query
	// FileAttributeTagInformation    FileInformationClass = 0x23 // Uses: Query
	FileIdBothDirectoryInformation FileInformationClass = 0x25 // Uses: Query
	// FileIdFullDirectoryInformation FileInformationClass = 0x26 // Uses: Query
	// FileValidDataLengthInformation FileInformationClass = 0x27 // Uses: Set
	// FileShortNameInformation       FileInformationClass = 0x28 // Uses: Set
)

func (c FileInformationClass) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c FileInformationClass) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type FileSystemInformationClass uint8

const (
	// FileFsVolumeInformation FileSystemInformationClass = 0x01 // Uses: Query
	// // FileFsLabelInformation       FileSystemInformationClass = 0x02
	FileFsSizeInformation FileSystemInformationClass = 0x03 // Uses: Query
	// FileFsDeviceInformation     FileSystemInformationClass = 0x04 // Uses: Query
	FileFsAttributeInformation FileSystemInformationClass = 0x05 // Uses: Query
// FileFsControlInformation    FileSystemInformationClass = 0x06 // Uses: Query Set
// FileFsFullSizeInformation   FileSystemInformationClass = 0x07 // Uses: Query
// FileFsObjectIdInformation   FileSystemInformationClass = 0x08 // Uses: Query Set
// FileFsDriverPathInformation FileSystemInformationClass = 0x09
// // FileFsVolumeFlagsInformation FileSystemInformationClass = 0x0A
// FileFsSectorSizeInformation FileSystemInformationClass = 0x0B // Uses: Query
)

// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/4718fc40-e539-4014-8e33-b675af74e3e1

type FileIdBothDirectoryInfo struct {

	//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/1e144bff-c056-45aa-bd29-c13d214ee2ba

	NextOffset      uint32
	FileIndex       uint32
	CreateTime      uint64
	LastAccessTime  uint64
	LastWriteTime   uint64
	LastChangeTime  uint64
	EndOfFile       uint64
	AllocationSize  uint64
	FileAttributes  FileAttributes
	FileNameLength  uint32 `smb:"len:FileName"`
	EASize          uint32
	ShortNameLength uint8
	Reserved1       uint8
	ShortName       []byte `smb:"fixed:24"`
	Reserved2       uint16
	FileId          uint64
	FileName        []byte
	Reserved3       uint16
}

type SMB2_FILE_ALL_INFO struct {
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/95f3056a-ebc1-4f5d-b938-3f68a44677a6
	//BasicInformation
	CreateTime     uint64
	LastAccessTime uint64
	LastWriteTime  uint64
	LastChangeTime uint64
	FileAttributes uint32
	Unknown        uint32
	//StandardInformation
	AllocationSize uint64
	EndOfFile      uint64
	NumberOfLinks  uint32
	DeletePending  uint8
	IsDirectory    uint8
	Reserved       uint16

	//InternalInformation
	FileID uint64

	EASize              uint32
	AccessMask          AccessMask
	PositionInformation uint64
	ModeInformation     uint32

	AlignmentInformation uint32
	FileNameLength       uint32 `smb:"len:FileName"`
	FileName             []byte
}

type FileBasicInformationX struct {
	CreateTime     uint64
	LastAccess     uint64
	LastWrite      uint64
	LastChange     uint64
	FileAttributes FileAttributes
	Reserved       uint32
}
type FileDispositionInformationX struct {
	//https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/12c3dd1c-14f6-4229-9d29-75fb2cb392f6
	DeletePending uint8
}
type FileRenameInformationX struct {
	// https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-fscc/52aa0b70-8094-4971-862d-79793f41e6a8
	ReplaceIfExists uint8
	Reserved        []byte `smb:"fixed:7"`
	RootDirHandle   uint64
	FileNameLength  uint32 `smb:"len:FileName"`
	FileName        []byte
}

func Duiqi4Byte(buf []byte) []byte {
	if len(buf)%4 != 0 {
		buf2 := make([]byte, (len(buf)/4+1)*4)
		copy(buf2, buf)
		return buf2
	}
	return buf
}

type FileStreamInformationX struct {
	//每次都需要4直接对齐
	NextOffset           uint32
	StreamNameLength     uint32 `smb:"len:StreamName"`
	StreamSize           uint64
	StreamAllocationSize uint64
	StreamName           []byte
	Reserved             uint32
}

// handle_QueryInfo
type InfoType uint8

const (
	SMB2_0_INFO_FILE       InfoType = 0x01 //FILE_INFO
	SMB2_0_INFO_FILESYSTEM InfoType = 0x02 //FS_INFO
	SMB2_0_INFO_SECURITY   InfoType = 0x03
	SMB2_0_INFO_QUOTA      InfoType = 0x04
)

func (c InfoType) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c InfoType) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

type FileFsAttributeInformationX struct {
	//https://wiki.wireshark.org/SMB2/SMB2_FS_ATTRIBUTE_INFO.md
	FSAttributes  uint32
	MaxNameLength uint32
	LabelLength   uint32 `smb:"len:FSName"`
	FSName        []byte
}
type FileFsSizeInformationX struct {
	AllocationSize uint64
	FreeUnits      uint64
	SectorsUnit    uint32
	BytesPerSector uint32
}

package smb

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"strings"

	"github/izouxv/smbapi/smb/encoder"
	"github/izouxv/smbapi/util"

	"github.com/izouxv/logx"
)

// 此文件提供ms-rpce封装
// DCE/RPC RPC over SMB 协议实现
// https://pubs.opengroup.org/onlinepubs/9629399/

// RPC over SMB 标准头
// type PDUHeader struct {
// 	StructureSize          uint16
// 	DataOffset             uint16 `smb:"offset:Buffer"`
// 	WriteLength            uint32 `smb:"len:Buffer"`
// 	FileOffset             []byte `smb:"fixed:8"`
// 	FileId                 []byte `smb:"fixed:16"` //16字节，服务端返回句柄
// 	Channel                uint32
// 	RemainingBytes         uint32
// 	WriteChannelInfoOffset uint16
// 	WriteChannelInfoLength uint16
// 	WriteFlags             uint32
// 	Buffer                 interface{} //写入的数据
// }

// DCE/RPC 标准头
type PDUHeaderStruct struct {
	Version            uint8
	VersionMinor       uint8
	PacketType         PDUType
	PacketFlags        uint8
	DataRepresentation uint32 //4字节，小端排序，0x10
	FragLength         uint16 //2字节，整个结构的长度
	AuthLength         uint16
	CallId             uint32

	Buffer interface{} //PDUBindStruct //PDUBindAckStruct//PDUResponseStruct
}

// 函数绑定结构
type PDUBindStruct struct {
	//PDUHeader
	MaxXmitFrag uint16 //4字节，发送大小协商
	MaxRecvFrag uint16 //4字节，接收大小协商
	AssocGroup  uint32
	NumCtxItems uint8
	Reserved    uint8
	Reserved2   uint16
	CtxItem     PDUCtxEItem
}

// PDU CtxItem结构
type PDUCtxEItem struct {
	ContextId      uint16
	NumTransItems  uint8
	Reserved       uint8
	AbstractSyntax PDUSyntaxID
	TransferSyntax PDUSyntaxID
}

type PDUSyntaxID struct {
	UUID    []byte `smb:"fixed:16"`
	Version uint32
}

type PDURequestStruct struct {
	//PDUHeader
	AllocHint uint32
	ContextID uint16
	Opnum     uint16      //15 is NetSharedEnumAll
	Buffer    interface{} //写入的数据
}
type PointerToServerUnc struct {
	ReferentId  uint32
	MaxCount    uint32
	Offset      uint32
	ActualCount uint32
	ServerUnc   string
}

var _ encoder.BinaryMarshallable = Status(0)

func (c *PointerToServerUnc) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	serverUNC := encoder.ToUnicode(c.ServerUnc)
	c.MaxCount = uint32(len(serverUNC))
	c.ActualCount = uint32(len(serverUNC))
	binary.Write(buf, binary.LittleEndian, c.ReferentId)
	binary.Write(buf, binary.LittleEndian, c.MaxCount)
	binary.Write(buf, binary.LittleEndian, c.Offset)
	binary.Write(buf, binary.LittleEndian, c.ActualCount)
	if len(c.ServerUnc) > 0 {
		buf.Write(serverUNC)
		return buf.Bytes(), nil
	}
	return buf.Bytes(), nil
}
func (c *PointerToServerUnc) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.LittleEndian, &c.ReferentId)
	binary.Read(buf, binary.LittleEndian, &c.MaxCount)
	binary.Read(buf, binary.LittleEndian, &c.Offset)
	binary.Read(buf, binary.LittleEndian, &c.ActualCount)
	name := make([]byte, c.ActualCount*2)
	buf.Read(name)
	c.ServerUnc, _ = encoder.FromUnicode(name)
	meta.CurrOffset += uint64(16 + len(name))
	// logx.Infof("unc: [%v]", c.ServerUnc)
	return c, nil
}

type PointerToResumeHandle struct {
	ReferentID   uint32
	ResumeHandle uint32
}
type NetShareEnumAllRequest struct {
	PointerToServerUnc

	Reserved       uint16
	PointertoLevel uint32 //level 1

	PointerToCtr PointerToCtr //[]byte `smb:"fixed:16"`
	MaxBuffer    uint32
	PointerToResumeHandle
}
type NetShareEnumAllResponse struct {
	PointertoLevel uint32        //level 1
	PointerToCtr   *PointerToCtr //  []byte `smb:"fixed:16"`

	// Reserved              uint16
	PointerToTotalentries uint32

	PointerToResumeHandle uint32
	Werr_OK               uint32
}
type PointerToCtr struct {
	Ctr            uint32
	Ctr1ReferentID uint32 //ctr1
	Ctr1Count      uint32
	info           *srvsvc_NetShareInfo1
}

func (p *PointerToCtr) SetInfo(names, comments []string) error {
	if len(names) != len(comments) {
		return fmt.Errorf("names not equal comments")
	}

	var Array []srvsvc_NetShareInfo1_ArrayItem
	for i := 0; i < len(names); i++ {
		Array = append(Array, srvsvc_NetShareInfo1_ArrayItem{
			PointerToName_Name:    []rune(names[i]),
			PointerToComment_Name: []rune(comments[i]),
		})
	}
	p.info = &srvsvc_NetShareInfo1{
		Array: Array,
	}
	return nil
}

var _ encoder.BinaryMarshallable = Status(0)

func (c *PointerToCtr) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {

	c.Ctr = 0x0001
	if c.info != nil {
		c.Ctr1Count = c.info.MaxCount
	}
	c.Ctr1ReferentID = 0x0001

	buf := bytes.NewBuffer(nil)
	binary.Write(buf, binary.LittleEndian, c.Ctr)
	binary.Write(buf, binary.LittleEndian, c.Ctr1ReferentID)
	binary.Write(buf, binary.LittleEndian, c.Ctr1Count)
	if c.info == nil {
		binary.Write(buf, binary.LittleEndian, uint32(0))
		return buf.Bytes(), nil
	}

	info := c.info
	info.MaxCount = uint32(len(info.Array))
	info.ReferentID = 0x0001

	binary.Write(buf, binary.LittleEndian, info.ReferentID)
	binary.Write(buf, binary.LittleEndian, info.MaxCount)

	for i := 0; i < int(info.MaxCount); i++ {
		item := &info.Array[i]
		item.PointerToName_ReferenceID = 0x001
		item.PointerToComment_ReferenceID = 0x001

		binary.Write(buf, binary.LittleEndian, item.PointerToName_ReferenceID)
		binary.Write(buf, binary.LittleEndian, item.Type)
		binary.Write(buf, binary.LittleEndian, item.PointerToComment_ReferenceID)
	}

	for i := 0; i < int(info.MaxCount); i++ {
		item := &info.Array[i]

		if true {
			//name
			size := uint32(len(item.PointerToName_Name))
			item.PointerToName_MaxCount = size + 1
			item.PointerToName_Offset = 0
			item.PointerToName_ActualCount = size + 1

			// logx.Printf("name: %v, len: %v", item.PointerToName_Name, len(item.PointerToName_Name))
			// for i, str := range item.PointerToName_Name {
			// 	logx.Printf("i: %v, char: %v", i, string(str))
			// }

			binary.Write(buf, binary.LittleEndian, item.PointerToName_MaxCount)
			binary.Write(buf, binary.LittleEndian, item.PointerToName_Offset)
			binary.Write(buf, binary.LittleEndian, item.PointerToName_ActualCount)
			name := encoder.ToUnicode(string(item.PointerToName_Name))
			buf.Write(name)
			//ouput 0x after name
			buf.Write(make([]byte, 2))

			if item.PointerToName_ActualCount%2 == 1 {
				//单数就对齐一下, 需要把对齐的写一下.
				padbuf := make([]byte, 2)
				buf.Write(padbuf)
			}
		}
		if true {
			//comment
			size := uint32(len(item.PointerToComment_Name))
			item.PointerToComment_MaxCount = size + 1
			item.PointerToComment_Offset = 0
			item.PointerToComment_ActualCount = size + 1
			binary.Write(buf, binary.LittleEndian, item.PointerToComment_MaxCount)
			binary.Write(buf, binary.LittleEndian, item.PointerToComment_Offset)
			binary.Write(buf, binary.LittleEndian, item.PointerToComment_ActualCount)
			name := encoder.ToUnicode(string(item.PointerToComment_Name))
			buf.Write(name)
			//ouput 0x after name
			buf.Write(make([]byte, 2))

			isEnd := int(info.MaxCount)-1 == i
			if item.PointerToComment_ActualCount%2 == 1 && !isEnd {
				//单数就对齐一下, 需要把对齐的写一下.
				padbuf := make([]byte, 2)
				buf.Write(padbuf)
			}
		}
	}

	return buf.Bytes(), nil
}
func (c *PointerToCtr) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	buf := bytes.NewBuffer(data)
	binary.Read(buf, binary.LittleEndian, &c.Ctr)
	binary.Read(buf, binary.LittleEndian, &c.Ctr1ReferentID)
	binary.Read(buf, binary.LittleEndian, &c.Ctr1Count)
	if c.Ctr1Count == 0 {
		meta.CurrOffset += 16
		return c, nil
	}

	info := &srvsvc_NetShareInfo1{}
	c.info = info
	binary.Read(buf, binary.LittleEndian, &info.ReferentID)
	binary.Read(buf, binary.LittleEndian, &info.MaxCount)

	info.Array = make([]srvsvc_NetShareInfo1_ArrayItem, int(info.MaxCount))
	for i := 0; i < int(info.MaxCount); i++ {
		item := &info.Array[i]
		binary.Read(buf, binary.LittleEndian, &item.PointerToComment_ReferenceID)
		binary.Read(buf, binary.LittleEndian, &item.Type)
		binary.Read(buf, binary.LittleEndian, &item.PointerToComment_ReferenceID)
	}

	for i := 0; i < int(info.MaxCount); i++ {
		item := &info.Array[i]

		if true {
			binary.Read(buf, binary.LittleEndian, &item.PointerToName_MaxCount)
			binary.Read(buf, binary.LittleEndian, &item.PointerToName_Offset)
			binary.Read(buf, binary.LittleEndian, &item.PointerToName_ActualCount)

			namebuf := make([]byte, (item.PointerToName_ActualCount)*2)
			buf.Read(namebuf)
			if item.PointerToName_ActualCount%2 == 1 {
				//单数就对齐一下, 需要把对齐的读取出来.
				padbuf := make([]byte, 2)
				buf.Read(padbuf)
			}

			name, err := encoder.FromUnicode(namebuf)
			if err != nil {
				return nil, err
			}
			if name[len(name)-1] == 0x00 {
				name = name[:len(name)-1]
			}
			printstr := func(name string) {
				logx.Printf("name len: %v", len(name))
				for i, str := range name {
					logx.Printf("string i: %v, char: %v", i, string(str))
				}
				r := []rune(name)
				fmt.Println(r)
				for i, str := range r {
					logx.Printf("run i: %v, char: %v", i, string(str))
				}
			}

			printstr(name)

			item.PointerToName_Name = []rune(name)
		}
		if true {
			binary.Read(buf, binary.LittleEndian, &item.PointerToComment_MaxCount)
			binary.Read(buf, binary.LittleEndian, &item.PointerToComment_Offset)
			binary.Read(buf, binary.LittleEndian, &item.PointerToComment_ActualCount)

			namebuf := make([]byte, (item.PointerToComment_ActualCount)*2)
			buf.Read(namebuf)
			if item.PointerToComment_ActualCount%2 == 1 {
				//单数就对齐一下, 需要把对齐的读取出来.
				padbuf := make([]byte, 2)
				buf.Read(padbuf)
			}

			name, err := encoder.FromUnicode(namebuf)
			if err != nil {
				return nil, err
			}
			if name[len(name)-1] == 0x00 {
				name = name[:len(name)-1]
			}
			item.PointerToComment_Name = []rune(name)
		}
	}

	return c, nil
}

type srvsvc_NetShareInfo1_ArrayItem struct {
	PointerToName_ReferenceID    uint32
	Type                         uint32
	PointerToComment_ReferenceID uint32

	PointerToName_MaxCount    uint32
	PointerToName_Offset      uint32
	PointerToName_ActualCount uint32
	PointerToName_Name        []rune //   string

	PointerToComment_MaxCount    uint32
	PointerToComment_Offset      uint32
	PointerToComment_ActualCount uint32
	PointerToComment_Name        []rune //   string
}
type srvsvc_NetShareInfo1 struct {
	ReferentID uint32
	MaxCount   uint32

	Array []srvsvc_NetShareInfo1_ArrayItem
}

type PDUResponseStruct struct {
	//PDUHeader
	AllocHint uint32
	ContextID uint16
	Opnum     uint16      //15 is NetSharedEnumAll
	Buffer    interface{} //写入的数据
}

// PDU CtxItem响应结构
type PDUCtxEItemResponseStruct struct {
	AckResult      uint16
	AckReason      uint16
	TransferSyntax []byte `smb:"fixed:16"` //16字节
	SyntaxVer      uint32
}

type PDUBindAckStruct struct {
	//https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

	MaxXmitFrag   uint16
	MaxRecvFrag   uint16
	AssocGroup    uint32
	ScndryAddrlen uint16
	ScndryAddr    []byte `smb:"count:ScndryAddrlen"` //取决管道的长度
	Reserved0     uint8  //这里的0-3我不确定会不会有问题.因为没找到文档.
	NumResults    uint8
	Reserved1     uint8
	Reserved2     uint8
	Reserved3     uint8
	CtxItem       PDUCtxEItemResponseStruct
}

type PDUType uint8

// PDU PacketType
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	PDURequest            PDUType = 0
	PDUPing               PDUType = 1
	PDUResponse           PDUType = 2
	PDUFault              PDUType = 3
	PDUWorking            PDUType = 4
	PDUNoCall             PDUType = 5
	PDUReject             PDUType = 6
	PDUAck                PDUType = 7
	PDUCl_Cancel          PDUType = 8
	PDUFack               PDUType = 9
	PDUCancel_Ack         PDUType = 10
	PDUBind               PDUType = 11
	PDUBind_Ack           PDUType = 12
	PDUBind_Nak           PDUType = 13
	PDUAlter_Context      PDUType = 14
	PDUAlter_Context_Resp PDUType = 15
	PDUShutdown           PDUType = 17
	PDUCo_Cancel          PDUType = 18
	PDUOrphaned           PDUType = 19
)

var _ encoder.BinaryMarshallable = PDUType(0)

func (c PDUType) MarshalBinary(meta *encoder.Metadata) ([]byte, error) {
	return MarshalBinary(c, meta, c)
}
func (c PDUType) UnmarshalBinary(data []byte, meta *encoder.Metadata) (interface{}, error) {
	return UnmarshalBinary(c, data, meta, c)
}

// PDU PacketFlags
// https://pubs.opengroup.org/onlinepubs/9629399/chap12.htm
const (
	PDUFlagReserved_01 = 0x01
	PDUFlagLastFrag    = 0x02
	PDUFlagPending     = 0x03
	PDUFlagFrag        = 0x04
	PDUFlagNoFack      = 0x08
	PDUFlagMayBe       = 0x10
	PDUFlagIdemPotent  = 0x20
	PDUFlagBroadcast   = 0x40
	PDUFlagReserved_80 = 0x80
)

// NDR 传输标准
// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-rpce/b6090c2b-f44a-47a1-a13b-b82ade0137b2
const (
	NDRSyntax   = "8a885d04-1ceb-11c9-9fe8-08002b104860" //Version 02, NDR64 data representation protocol
	NDR64Syntax = "71710533-BEBA-4937-8319-B5DBEF9CCC36" //Version 01, NDR64 data representation protocol
)

// 处理PDU uuid 转成字节数组
func PDUUuidFromBytes(uuid string) []byte {
	s := strings.ReplaceAll(uuid, "-", "")
	b, _ := hex.DecodeString(s)
	r := []byte{b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]}
	return r
}

func DcerpcRead(ctx *DataCtx, r *ReadRequest) (interface{}, error) {

	pdb := ctx.session.pdb
	var pdudata []byte
	var err error
	switch pdb.PacketType {
	case PDUBind:
		bind := pdb.Buffer.(PDUBindStruct)
		ScndryAddr := append([]byte("\\PIPE\\srvsvc"), 0x0)
		NDRSyntaxData := PDUUuidFromBytes(NDRSyntax)

		var pduAck = &PDUBindAckStruct{
			MaxXmitFrag:   bind.MaxXmitFrag,
			MaxRecvFrag:   bind.MaxRecvFrag,
			AssocGroup:    bind.AssocGroup,
			ScndryAddrlen: uint16(len(ScndryAddr)),
			ScndryAddr:    ScndryAddr, //[]byte `smb:"count:ScndryAddrlen"` //取决管道的长度
			NumResults:    1,          //uint8
			CtxItem: PDUCtxEItemResponseStruct{
				AckResult:      0,
				TransferSyntax: NDRSyntaxData,
				SyntaxVer:      2,
			},
		}

		fragLength := uint16(16 + util.SizeOfStruct(*pduAck))

		var pdu = PDUHeaderStruct{
			Version:      pdb.Version,
			VersionMinor: pdb.VersionMinor,
			PacketType:   PDUBind_Ack, //Bind_ack

			PacketFlags:        pdb.PacketFlags,
			DataRepresentation: pdb.DataRepresentation,
			FragLength:         fragLength, //   68, //  pdb.FragLength,
			AuthLength:         pdb.AuthLength,
			CallId:             pdb.CallId,
			Buffer:             pduAck,
		}

		pdudata, err = encoder.Marshal(pdu)
		if err != nil {
			return nil, err
		}
	case PDURequest:

		// request := pdb.Buffer.(PDURequestStruct)
		// var info = &srvsvc_NetShareInfo1{}

		ptc := &PointerToCtr{}

		var names = []string{
			// "IPC$",
			// "Documents",
		}
		var comments = []string{
			// "IPC Service",
			// "",
		}

		for _, anchor := range ctx.session.anchors {
			names = append(names, anchor.Name)
			comment := ""
			if anchor.Name == NamedPipeShareName {
				comment = "IPC Service"
			}
			comments = append(comments, comment)
		}

		ptc.SetInfo(names, comments)

		shareEnumAllResp := NetShareEnumAllResponse{
			PointertoLevel:        1,
			PointerToTotalentries: 2,
			PointerToCtr:          ptc,
		}

		ptcBuf, err := encoder.Marshal(shareEnumAllResp)
		if err != nil {
			return nil, err
		}

		var response = &PDUResponseStruct{
			AllocHint: uint32(len(ptcBuf)),
			Buffer:    shareEnumAllResp,
			// Buffer:    &NetShareEnumAllResponse{PointerToCtr: ptc},
		}

		fragLength := uint16(24 + len(ptcBuf))

		var pdu = PDUHeaderStruct{
			Version:      pdb.Version,
			VersionMinor: pdb.VersionMinor,
			PacketType:   PDUResponse,

			PacketFlags:        pdb.PacketFlags,
			DataRepresentation: pdb.DataRepresentation,
			FragLength:         fragLength, //  68, //  pdb.FragLength,
			AuthLength:         pdb.AuthLength,
			CallId:             pdb.CallId,
			Buffer:             response,
		}

		pdudata, err = encoder.Marshal(pdu)
		if err != nil {
			return nil, err
		}

	default:
		return nil, fmt.Errorf("Not Support")
	}

	resp := ReadResponse{
		Header:        r.Header,
		StructureSize: 0x0011,
		DataOffset:    0x0050,
		DataLength:    uint32(len(pdudata)),
		Data:          pdudata,
	}
	return &resp, nil
}

func DcerpcWrite(ctx *DataCtx, r *WriteRequest) (interface{}, error) {

	buf := r.Data

	fragType := PDUType(buf[2])
	switch fragType {
	case PDUBind:
		var bind = &PDUBindStruct{}
		var pdb = PDUHeaderStruct{
			Buffer: bind,
		}
		if err := encoder.Unmarshal(buf, &pdb); err != nil {
			return nil, err
		}
		ctx.session.pdb = pdb
	case PDURequest:
		var PointerToCtr PointerToCtr

		var pdb = PDUHeaderStruct{
			Buffer: &PDURequestStruct{
				Buffer: &NetShareEnumAllRequest{
					PointerToCtr: PointerToCtr,
				},
			},
		}
		if err := encoder.Unmarshal(buf, &pdb); err != nil {
			return nil, err
		}
		ctx.session.pdb = pdb

	default:
		return nil, fmt.Errorf("Not Support")
	}

	resp := WriteResponse{
		Count:         uint32(len(buf)),
		Header:        r.Header,
		StructureSize: 0x0011,
	}
	return &resp, nil
}

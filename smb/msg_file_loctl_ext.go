package smb

const (
	RPC_VERSION       = 5
	RPC_VERSION_MINOR = 0

	RPC_TYPE_REQUEST  = 0
	RPC_TYPE_RESPONSE = 2
	RPC_TYPE_BIND     = 11
	RPC_TYPE_BIND_ACK = 12

	RPC_PACKET_FLAG_FIRST = 0x01
	RPC_PACKET_FLAG_LAST  = 0x02

	SRVSVC_VERSION       = 3
	SRVSVC_VERSION_MINOR = 0

	NDR_VERSION = 2

	OP_NET_SHARE_ENUM = 15
)

var (
	SRVSVC_UUID = []byte("c84f324b7016d30112785a47bf6ee188")
	NDR_UUID    = []byte("045d888aeb1cc9119fe808002b104860")
)

type Bind struct {
	VERSION            uint8
	VERSION_MINOR      uint8
	PACKET_TYPE_BIND   uint8
	PACKET_FLAGS       uint8
	DataRepresentation uint32
	FragLength         uint16
	AuthLength         uint16
	CallId             uint32
	MaxXmitFrag        uint16
	MaxRecvFrag        uint16
	AssocGroup         uint32
	NumCtxItems        uint32
}

// type Bind struct {
// 	CallId uint32
// }

// func (r *Bind) Size() int {
// 	return 72
// }

// func (r *Bind) Encode(b []byte) {
// 	b[0] = RPC_VERSION
// 	b[1] = RPC_VERSION_MINOR
// 	b[2] = RPC_TYPE_BIND
// 	b[3] = RPC_PACKET_FLAG_FIRST | RPC_PACKET_FLAG_LAST

// 	// order = Little-Endian, float = IEEE, char = ASCII
// 	b[4] = 0x10
// 	b[5] = 0
// 	b[6] = 0
// 	b[7] = 0

// 	le.PutUint16(b[8:10], 72)        // frag length
// 	le.PutUint16(b[10:12], 0)        // auth length
// 	le.PutUint32(b[12:16], r.CallId) // call id
// 	le.PutUint16(b[16:18], 4280)     // max xmit frag
// 	le.PutUint16(b[18:20], 4280)     // max recv frag
// 	le.PutUint32(b[20:24], 0)        // assoc group
// 	le.PutUint32(b[24:28], 1)        // num ctx items
// 	le.PutUint16(b[28:30], 0)        // ctx item[1] .context id
// 	le.PutUint16(b[30:32], 1)        // ctx item[1] .num trans items

// 	hex.Decode(b[32:48], SRVSVC_UUID)
// 	le.PutUint16(b[48:50], SRVSVC_VERSION)
// 	le.PutUint16(b[50:52], SRVSVC_VERSION_MINOR)

// 	hex.Decode(b[52:68], NDR_UUID)
// 	le.PutUint32(b[68:72], NDR_VERSION)
// }

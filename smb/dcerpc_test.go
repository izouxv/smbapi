package smb

import (
	"bytes"
	"encoding/hex"
	"github/izouxv/smbapi/smb/encoder"
	"github/izouxv/smbapi/util"
	"testing"
)

func Test_srvsvc_NetShareCtr(t *testing.T) {
	netShareCtrHex := "01000000010000000200000002000000020000000100000003000080020000000100000000000000020000000500000000000000050000004900500043002400000000000c000000000000000c0000004900500043002000530065007200760069006300650000000a000000000000000a00000044006f00630075006d0065006e007400730000000100000000000000010000000000"
	netShareCtrHex = "0100000001000000050000000100000005000000010000000300008001000000010000000000008001000000010000000000008001000000010000000000000001000000010000000000004001000000050000000000000005000000490050004300240000000000010000000000000001000000000000000d000000000000000d0000004d006100630069006e0074006f007300680020004800440000000000010000000000000001000000000000000600000000000000060000005600610075006c0074000000010000000000000001000000000000001300000000000000130000007a0078001920730020005000750062006c0069006300200046006f006c0064006500720000000000010000000000000001000000000000000300000000000000030000007a007800000000000100000000000000010000000000"
	netShareCtrBytes := util.BytesFromHex(netShareCtrHex)

	var ctl PointerToCtr
	err := encoder.Unmarshal(netShareCtrBytes, &ctl)
	if err != nil {
		t.Fatalf("err")
	}
	data, err := encoder.Marshal(&ctl)
	if err != nil {
		t.Fatalf("err")
	}
	if !bytes.Equal(data, netShareCtrBytes) {
		t.Fatalf("err, new data: \n%v\n, orig: \n%v\n", hex.Dump(data), hex.Dump(netShareCtrBytes))
	}
}
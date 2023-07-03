package smb

import (
	"github/izouxv/smbapi/util"
	"testing"
)

func Test_Ser(t *testing.T) {
	create := "fe534d4240000100000000000500000108000000980000000e00000000000000fffe0000010000000a0000001fdec2cc3c6bffb1ec41e0e751573c3340fc1c1539000000020000000000000000000000000000000000000080000000100000000700000001000000010000007800000080000000180000000000000000000000000000001000040000000000000000004d78416300000000"
	getinfo := "fe534d424000010000000000100000010c000000680000000f00000000000000fffe0000010000000a0000001fdec2ccaa413134ea97bc853825da5c99e5f826290001120000010000000000000000000000000000000000ffffffffffffffffffffffffffffffff"
	close := "fe534d424000010000000000060000010c000000000000001000000000000000fffe0000010000000a0000001fdec2cc45eb912f4175c41bb1dcb520cd6b3b8a1800000000000000ffffffffffffffffffffffffffffffff"

	allhex := create + getinfo + close
	allbytes := util.BytesFromHex(allhex)

	session := NewSessionServer(true, nil, nil, nil)
	session.sessionID = 0xccc2de1f0000000a
	var ctx = &DataCtx{
		session: session,
		handle:  config.Handle,
	}

	_, _, stat := ActionParserFunc(ctx, allbytes)
	if stat != StatusOk {
		t.Fatalf("err")
	}

	// resp, err := ActionFunc(ctx, allbytes)
	// if err != nil {
	// 	t.Fatalf("err")
	// }
	// t.Logf("resp: %v", resp)

}

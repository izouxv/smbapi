package smb

import (
	"testing"

	"github/izouxv/smbapi/util"

	"github.com/stretchr/testify/assert"
)

func Test_Create(t *testing.T) {
	create := "fe534d4240000100000000000500000100000000980000000900000000000000fffe0000000000009855fc995b7b1a170000000000000000000000000000000039000000020000000000000000000000000000000000000080000000100000000700000001000000010000007800000080000000180000000000000000000000000000001000040000000000000000004d78416300000000"
	getinfo := "fe534d4240000100000000001000000104000000680000000a00000000000000fffe0000000000009855fc995b7b1a1700000000000000000000000000000000290001120000010000000000000000000000000000000000ffffffffffffffffffffffffffffffff"
	close := "fe534d4240000100000000000600000104000000000000000b00000000000000fffe0000000000009855fc995b7b1a17000000000000000000000000000000001800000000000000ffffffffffffffffffffffffffffffff"

	allhex := create + getinfo + close
	allbytes := util.BytesFromHex(allhex)

	session := NewSessionServer(true, nil, nil, nil)
	session.sessionID = 0x171a7b5b99fc5598
	var ctx = &DataCtx{
		session: session,
		handle:  config.Handle,
	}

	resp, _, stat := ActionParserFunc(ctx, allbytes)
	if stat != StatusOk {
		t.Fatalf("err")
	}
	t.Logf("resp: %v", resp)
}
func Test_Xattr(t *testing.T) {
	// Filename := ":com.apple.metadata\uf022_kMDItemUserTags"
	Filename := ":" + "com.apple.metadata\uf022_kMDItemUserTags"
	ok, path, xattr := IsXAttr(Filename)
	assert.Equal(t, ok, true)
	assert.Equal(t, path, "")
	assert.Equal(t, xattr, Filename)
}

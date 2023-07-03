package smb

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"testing"

	"github/izouxv/smbapi/smb/encoder"

	"github.com/izouxv/logx"
	"github.com/stretchr/testify/assert"
)

func Test_query_info(t *testing.T) {
	filename := "names"

	var info = SMB2_FILE_ALL_INFO{
		FileName: encoder.ToUnicode(filename),
	}
	infobuf, err := encoder.Marshal(info)
	if err != nil {
		t.Fatalf("err")
	}
	var info2 = SMB2_FILE_ALL_INFO{}
	err = encoder.Unmarshal(infobuf, &info2)
	if err != nil {
		t.Fatalf("err")
	}
	if !bytes.Equal(info2.FileName, info.FileName) {
		t.Fatalf("err")
	}

	resp := QueryInfoResponse{
		StructureSize: 9,
		OutputBuffer:  infobuf,
	}
	respBuf, err := encoder.Marshal(resp)
	if err != nil {
		t.Fatalf("err")
	}

	fmt.Printf("%v", hex.Dump(respBuf))

}

func Test_path(t *testing.T) {
	tmpfile, err := ioutil.TempFile("", "xattr_Test")
	assert.Equal(t, nil, err)
	logx.Printf("f name: %v", tmpfile.Name())
	logx.Printf("f: %v", tmpfile)
}

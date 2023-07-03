package smb

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"

	"github/izouxv/smbapi/ntlmssp"
	"github/izouxv/smbapi/smb/encoder"
)

func Test_Auth(t *testing.T) {

	var (
		Domain      = ""
		User        = "name"
		Workstation = "xxxxx"
		Password    = "pwd"
		challenge   = ntlmssp.NewChallenge(0)
	)

	auth := ntlmssp.NewAuthenticatePass(Domain, User, Workstation, Password, challenge)

	responseToken, err := encoder.Marshal(auth)
	if err != nil {
		t.Fatalf("err")
	}
	fmt.Printf("%v", hex.Dump(responseToken))
	var ntlmsspnegAuth ntlmssp.Authenticate
	if err := encoder.Unmarshal(responseToken, &ntlmsspnegAuth); err != nil {
		t.Fatalf("err")
	}
	if !bytes.Equal(ntlmsspnegAuth.UserName, auth.UserName) {
		t.Fatalf("err")
	}
}

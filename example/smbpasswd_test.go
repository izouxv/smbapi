package example

import (
	"github/izouxv/smbapi/ntlmssp"
	"testing"
)

func Test_SMBPASSWD(t *testing.T) {
	t.Logf("test password: %x", ntlmssp.Ntowfv1("password"))
}

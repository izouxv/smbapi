package smb

import (
	"fmt"
	"net/http"

	"github/izouxv/smbapi/util"

	"golang.org/x/net/webdav"
)

const (
	UserName    = "name"
	UserPwd     = "pwd"
	PORT_iphone = 445
	PORT_mac    = 10445
)

var config *Config

func init() {
	Logger := func(r *http.Request, err error) {
		if err != nil {
			//	logx.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
		} else {
			//	logx.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
		}
	}

	pwd := util.PWDR()
	anchor1 := NewAnchor("TestDir1", pwd)
	anchor2 := NewAnchor("TestDir2", pwd)

	config = &Config{
		// Port: PORT,
		Pwd: func(name string) (string, error) {
			if UserName == name {
				return UserPwd, nil
			}
			return "", fmt.Errorf("not found")
		},
		Tree: func(userName string) ([]*Anchor, error) {
			anchorIPC := NewAnchor(NamedPipeShareName, pwd)
			return []*Anchor{
				anchor1,
				anchor2,
				anchorIPC,
			}, nil
		},
		Handle: func(path string) *Handler {
			return &Handler{&webdav.Handler{
				Logger:     Logger,
				Prefix:     "/" + anchor1.Name + "/",
				FileSystem: webdav.Dir("/"),
				LockSystem: webdav.NewMemLS(),
			}}
		},
	}
}

package example

import (
	"fmt"
	iofs "io/fs"
	"log"
	"net"
	"net/http"
	"testing"
	"time"

	"github/izouxv/smbapi/smb"
	"github/izouxv/smbapi/util"

	"github.com/hirochachacha/go-smb2"
	"golang.org/x/net/webdav"
)

// https://support.apple.com/en-sg/guide/mac-help/mchlp1654/mac
// nfs://localhost:10446

const (
	UserName    = "name"
	UserPwd     = "pwd"
	PORT_iphone = 4450
	PORT_mac    = 10445
	// PORT     = 10445 //mac not 445
	// PORT = 445 //ios is const 445

)

var config *smb.Config

func init() {
	Logger := func(r *http.Request, err error) {
		if err != nil {
			//	logx.Printf("WEBDAV [%s]: %s, ERROR: %s\n", r.Method, r.URL, err)
		} else {
			//	logx.Printf("WEBDAV [%s]: %s \n", r.Method, r.URL)
		}
	}

	pwd := util.PWDR()
	anchor1 := smb.NewAnchor("TestDir1", pwd)
	anchor2 := smb.NewAnchor("TestDir2", pwd)

	config = &smb.Config{
		Pwd: func(name string) (string, error) {
			if UserName == name || name == "apple" {
				return UserPwd, nil
			}
			return "", fmt.Errorf("not found")
		},
		Tree: func(userName string) ([]*smb.Anchor, error) {
			anchorIPC := smb.NewAnchor(smb.NamedPipeShareName, pwd)
			return []*smb.Anchor{
				anchor1,
				anchor2,
				anchorIPC,
			}, nil
		},
		Handle: func(path string) *smb.Handler {
			return &smb.Handler{
				&webdav.Handler{
					Logger:     Logger,
					Prefix:     "/" + anchor1.Name + "/",
					FileSystem: webdav.Dir("/"),
					LockSystem: webdav.NewMemLS(),
				},
			}
		},
	}
}

func Test_SMB(t *testing.T) {
	ser := smb.NewServer(config)
	go ser.Start(PORT_iphone)
	go ser.Start(PORT_mac)

	if true {
		time.Sleep(time.Second * 2)
		// startClient1(t)
		startClient2(t)
	}
	select {}
}

func startClient2(t *testing.T) {
	conn, err := net.Dial("tcp", "localhost:10445")
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     UserName,
			Password: UserPwd,
		},
	}

	s, err := d.Dial(conn)
	if err != nil {
		panic(err)
	}
	defer s.Logoff()

	fs, err := s.Mount("TestDir1")
	if err != nil {
		panic(err)
	}
	defer fs.Umount()

	matches, err := iofs.Glob(fs.DirFS("."), "*")
	if err != nil {
		panic(err)
	}
	for _, match := range matches {
		fmt.Println(match)
	}

	err = iofs.WalkDir(fs.DirFS("."), ".", func(path string, d iofs.DirEntry, err error) error {
		fmt.Println(path, d, err)

		return nil
	})
	if err != nil {
		panic(err)
	}
}
func startClient1(t *testing.T) {

	host := "127.0.0.1"
	options := smb.Options{
		Host:        host,
		Port:        PORT_mac,
		User:        UserName,
		Workstation: "xxxxx",
		Password:    UserPwd,
		// Domain:      "corp",
		// Domain:      "localhost",
		// Hash:        ntlmssp.NTPasswordHash(UserPwd),
	}

	debug := false
	session, err := smb.NewSessionClient(options, debug)
	if err != nil {
		log.Fatalln("[!]", err)
	}
	defer session.Close()

	if session.IsSigningRequired {
		log.Println("[-] Signing is required")
	} else {
		log.Println("[+] Signing is NOT required")
	}

	if session.IsAuthenticated {
		log.Printf("\n\n\n Simple Login successful\n\n\n")
	} else {
		log.Println("[-] Login failed")
	}

	if err != nil {
		log.Fatalln("[!]", err)
	}

}

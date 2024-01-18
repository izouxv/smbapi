# SMB2
!!! NOT MAINTEN

A Go package for smb server. 

Currently test pass with iphone files. 

mac 12.6.8

Here is a sample code from smb server:

```go


var config *smb.Config

func init() {
	Logger := func(r *http.Request, err error) {
		if err != nil { 
		} else { 
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

ser := smb.NewServer(config)
go ser.Start(445)


```

package smb

import (
	"io/ioutil"
	"os"
	"reflect"
	"testing"

	"github/izouxv/smbapi/util"

	"github.com/izouxv/logx"
	"github.com/kormoc/xattr"
)

func Test_2XAttr(t *testing.T) {
	path := "demo_info.log:com.apple.lastuseddate#PS"
	ok, path, xattr := IsXAttr(path)
	logx.Printf("ok: %v, path: %v, xattr: %v", ok, path, xattr)
}
func Test_XAttr(t *testing.T) {

	// https://blog.csdn.net/lovechris00/article/details/113060237
	// name@name IMG % xattr ./Screen\ Shot\ 2022-08-13\ at\ 06.46.31.png
	// com.apple.FinderInfo
	// com.apple.lastuseddate#PS
	// com.apple.macl
	// com.apple.metadata:kMDItemIsScreenCapture
	// com.apple.metadata:kMDItemScreenCaptureGlobalRect
	// com.apple.metadata:kMDItemScreenCaptureType
	// xattr -p com.apple.lastuseddate#PS ./Screen\ Shot\ 2022-08-13\ at\ 06.46.31.png 查询属性
	// xattr -w com.apple.TExtEncoding utf-9 ./xxx.md //添加/修改属性
	// xattr -d com.apple.quarantine ./xxx.md  删除文件某属性
	// xattr -dr com.apple.quarantine dirName  递归删除文件下的所有文件的某属性
	// xattr -p com.apple.FinderInfo -x ./png.png

	var test_xattrName = "user.xattr.test"
	var test_xattrValue = []byte{11, 22, 33, 44, 55, 66, 77, 88, 99}

	tmpfile, err := ioutil.TempFile("", "xattr_Test")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(tmpfile.Name())

	if err := xattr.SetBytes(tmpfile.Name(), test_xattrName, test_xattrValue); err != nil {
		t.Fatalf("SetBytes failed: %v\n", err)
	}

	if value, err := xattr.GetBytes(tmpfile.Name(), test_xattrName); !reflect.DeepEqual(value, test_xattrValue) {
		t.Fatalf("GetBytes failed: %v\n\tExpected: '%v'\n\tFound: '%v'\n", err, test_xattrValue, value)
	}

	list, err := xattr.ListBytes(tmpfile.Name())
	if err != nil {
		t.Fatalf("Remove failed: %v\n", err)
	}
	logx.Printf("list: %v", string(list))

	if err := xattr.Remove(tmpfile.Name(), test_xattrName); err != nil {
		t.Fatalf("Remove failed: %v\n", err)
	}

	pngPath := util.PWDR() + "/IMG/png.png"

	value, err := xattr.GetBytes(pngPath, string(XATTR_PS_EA_NAME))
	if err != nil {
		t.Fatalf("Remove failed: %v\n", err)
	}
	logx.Printf("value: %v", value)

}

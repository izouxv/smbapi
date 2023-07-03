package smb

import (
	"fmt"
)

var (
	ErrStructSizeInvalid    = fmt.Errorf("ErrStructSizeInvalid")
	ErrHeaderSmb1           = fmt.Errorf("ErrHeaderSmb1")
	ErrHeaderSessionIdError = fmt.Errorf("ErrHeaderSessionIdError")
	ErrDataParserError      = fmt.Errorf("ErrDataParserError")
)

package smb

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"net"
	"path/filepath"
	"strings"
	"time"

	"github/izouxv/smbapi/gss"
	"github/izouxv/smbapi/smb/encoder"

	"github.com/izouxv/logx"
	"golang.org/x/net/webdav"
)

type HookCondition int

const (
	FileClose HookCondition = iota
)

type SessionS struct {
	session

	fileNum uint64
	//tree
	openedFiles map[GUID]webdav.File
	srvsvc      GUID

	//server level
	SessionKey      []byte
	ServerChallenge uint64
	getPwd          GetPwdFunc
	getTree         GetAnchorFun
	anchors         map[string]*Anchor
	activeAnchorKey string //当前的anchor

	//current anchor key, TODO 每次切换的时候都会新建一个tree. 但是这个treeid不会变. 来回切换anchor多线程怎么处理? 还没理解.

	//dcerpc for IPC$
	pdb PDUHeaderStruct

	notify map[GUID]*ChangeNotifyRequest
}

func NewSessionServer(debug bool, conn net.Conn, getPwd GetPwdFunc, getTree GetAnchorFun) (s *SessionS) {
	s = &SessionS{
		session: session{
			IsSigningRequired: false,
			IsAuthenticated:   false,
			debug:             debug,
			securityMode:      0,
			sessionID:         uint64(time.Now().UnixNano()),
			dialect:           0,
			conn:              conn,
		},
		anchors:     make(map[string]*Anchor),
		openedFiles: make(map[GUID]webdav.File),
		notify:      make(map[GUID]*ChangeNotifyRequest),
		getPwd:      getPwd,
		getTree:     getTree,
		// latestFileId: NilGUID,
	}

	s.Debug("Negotiating protocol", nil)

	return s
}

func (s *SessionS) NegotiateProtocolServer() (err error) {
	//TODO 在这里做所有协议的nego. 需要通过OID来判断, 不管多少个流程, 都在这一个函数里处理.
	s.Debug("Sending NegotiateProtocolServer2 request", nil)

	rw := bufio.NewReadWriter(bufio.NewReader(s.conn), bufio.NewWriter(s.conn))

	simpleReqAction := func(reqMsg []byte, cmd Command, data DataI) error {
		ctx := NewDataCtx(s, s.conn, nil)
		err = encoder.Unmarshal(reqMsg, data)
		if err != nil {
			return err
		}
		respBuf, err := ServerAction(ctx, cmd, data)
		if err != nil {
			return err
		}
		// logx.Printf("respBuf: \n%v", hex.Dump(respBuf))
		return s.Send(respBuf, rw)
	}

	simpleReq := func(data DataI, cmd Command) error {
		reqMsg, _, err := s.Recv(rw)
		if err != nil {
			return err
		}
		return simpleReqAction(reqMsg, cmd, data)
	}

	reqMsg, ver, err := s.Recv(rw)
	if err != nil {
		return err
	}
	if ver == ProtocolSmb {
		//优先处理smb1
		var reqSmb1Negotiate NegotiateSmb1Request
		if err = simpleReqAction(reqMsg, CommandNegotiate, &reqSmb1Negotiate); err != nil {
			logx.Errorf("reqNegotiate, err: %v", err)
			return err
		}
		//处理完后，再取新数据
		reqMsg, ver, err = s.Recv(rw)
		if err != nil {
			return err
		}
	}
	var reqNegotiate NegotiateRequest
	if err = simpleReqAction(reqMsg, CommandNegotiate, &reqNegotiate); err != nil {
		logx.Errorf("reqNegotiate, err: %v", err)
		return err
	}

	// var reqNegotiate NegotiateRequest
	// if data, ver, err = simpleReq(&reqNegotiate); err != nil {
	// 	if err != nil && ver == ProtocolSmb {
	// 		var reqSmb1Negotiate NegotiateSmb1Request
	// 	} else {
	// 		logx.Errorf("reqNegotiate, err: %v", err)
	// 		return err
	// 	}
	// }

	requestSetUp1 := SessionSetup1Request{SecurityBlob: &gss.NegTokenInit{}}
	if err = simpleReq(&requestSetUp1, CommandSessionSetup); err != nil {
		logx.Errorf("requestSetUp1, err: %v", err)
		return err
	}

	requestSetUp2 := SessionSetup2Request{SecurityBlob: &gss.NegTokenResp{}}
	if err = simpleReq(&requestSetUp2, CommandSessionSetup); err != nil {
		logx.Errorf("requestSetUp2, err: %v", err)
		return err
	}
	return nil
}

func (session *SessionS) SetActiveAnchorKey(activeAnchorKey string) bool {
	_, ok := session.anchors[activeAnchorKey]
	if ok {
		session.activeAnchorKey = activeAnchorKey
	}
	return ok
}
func (session *SessionS) GetAbsPath(path string) string {
	anchor, _ := session.anchors[session.activeAnchorKey]
	root := anchor.RootPath
	fullpath := filepath.Join(root, filepath.ToSlash(path))
	return fullpath
}
func (session *SessionS) SetAnchor(fileNum uint64, items []*Anchor) {
	for _, item := range items {
		session.anchors[strings.ToUpper(item.Name)] = item
	}
}

func (s *SessionS) GetAnchor(name string) *Anchor {
	item, ok := s.anchors[name]
	if !ok {
		return nil
	}
	return item
}

type DataCtx struct {
	session *SessionS
	conn    net.Conn
	handle  func(string) *Handler

	//batch message var
	latestFileId GUID
	closeAction  func()
}

func (d *DataCtx) Handle() *Handler {
	return d.handle(d.session.activeAnchorKey)
}

func (s *DataCtx) IsVer_2_1() bool {
	return s.session.dialect == uint16(DialectSmb_2_1)
}
func (s *DataCtx) IsVer_2_0() bool {
	return s.session.dialect == uint16(DialectSmb_2_0_2)
}
func (s *DataCtx) FileID(fileid GUID) GUID {
	if fileid.IsEqual(LastGUID) {
		fileid = s.latestFileId
	}
	return fileid
}

func NewDataCtx(s *SessionS, conn net.Conn, Handle func(string) *Handler) *DataCtx {
	return &DataCtx{session: s, conn: conn, handle: Handle, latestFileId: NilGUID}
}

type DataI interface {
	ServerAction(ctx *DataCtx) (interface{}, error)
}

var commandRequestMap = make(map[Command]func() DataI)

// //////////////////////

func ActionParserFunc(ctx *DataCtx, msgs []byte) ([]DataI, []Command, Status) {
	tmp := msgs
	var items []DataI
	var cmds []Command
	for {
		if tmp == nil {
			break
		}
		chainOffset := binary.LittleEndian.Uint32(tmp[20:])
		oneMsg := tmp
		if chainOffset > 0 {
			oneMsg = tmp[:chainOffset]
			tmp = tmp[chainOffset:]
		} else {
			tmp = nil
		}

		item, stat, cmd := ActionParserOneMsgFunc(ctx, oneMsg)
		if stat != StatusOk {
			return nil, nil, stat
		}
		cmds = append(cmds, cmd)
		items = append(items, item)
	}
	return items, cmds, StatusOk
}

func ActionFunc(ctx *DataCtx, msgs []byte) ([]byte, Command, Status) {
	//有可能是多个消息合并到一起. 需要单独分开.

	var respTotal [][]byte
	datas, cmds, stat := ActionParserFunc(ctx, msgs)
	if stat != StatusOk {
		return nil, 0, stat
	}

	for i, data := range datas {
		cmd := cmds[i]
		respBuf, err := ServerAction(ctx, cmd, data)
		if err != nil {
			return nil, 0, STATUS_INVALID_PARAMETER
		}
		respTotal = append(respTotal, respBuf)
	}

	//change chain offset
	for i := 0; i < len(respTotal); i++ {
		resp := respTotal[i]
		if i != len(respTotal)-1 {
			binary.LittleEndian.PutUint32(resp[20:], uint32(len(resp)))
		}
	}

	return bytes.Join(respTotal, []byte{}), cmds[0], StatusOk

}
func ActionParserOneMsgFunc(ctx *DataCtx, msg []byte) (dd DataI, ss Status, cc Command) {
	commandNum := binary.LittleEndian.Uint16(msg[12:])
	command := Command(commandNum)

	sessionId := binary.LittleEndian.Uint64(msg[40:])

	if ctx.session.sessionID != sessionId {
		return nil, StatusUserSessionDeleted, command
		// binary.LittleEndian.PutUint32(msg[8:], uint32(StatusUserSessionDeleted))
		// return nil, msg, nil
	}

	Flags := binary.LittleEndian.Uint32(msg[16:])
	if Flags&^uint32(SMB2_FLAGS_PRIORITY_MASK) != 0 {
		// binary.LittleEndian.PutUint32(msg[8:], uint32(STATUS_NOT_SUPPORTED))
		// return nil, msg, nil

	}

	fff, ok := commandRequestMap[command]
	if !ok {
		return nil, STATUS_NOT_IMPLEMENTED, command
		// binary.LittleEndian.PutUint32(msg[8:], uint32(STATUS_NOT_IMPLEMENTED))
		// return nil,
	}

	data := fff()
	_, err := encoder.Unmarshal2(msg, data)
	if err != nil {
		return nil, STATUS_INVALID_PARAMETER, command
	}

	return data, StatusOk, command

	// return ServerAction(ctx, msg, data)

}

var signaturBlank = make([]byte, 16)

func ServerAction(ctx *DataCtx, cmd Command, data DataI) (bbb []byte, eee error) {

	startTime := time.Now()

	logx.Infof("[CMD] cmd, %v", cmd)

	defer func() {
		takeT := time.Since(startTime)
		if takeT > 100*time.Millisecond {
			logx.Printf("[TIME] command: %v, taketime: %v", cmd, takeT)
		}
		if eee != nil {
			logx.Infof("[CMD] data, %v, ss: %v, err: %v", cmd, eee, eee)
		}
	}()

	resp, err := data.ServerAction(ctx)
	if err != nil {
		return nil, err
	}
	respBuf, err := encoder.Marshal(resp)
	if err != nil {
		return nil, err
	}

	if true {
		// // copy(respBuf[48:64], signaturBlank)
		// //sign
		// if len(ctx.session.SessionKey) > 0 {
		// 	content := respBuf[64:]
		// 	sig, err := CalculateSignature(ctx.session.SessionKey, content, ctx.session.dialect)
		// 	if err != nil {
		// 		logx.Errorf("err: %v", err)
		// 		return nil, err
		// 	}
		// 	copy(respBuf[48:64], sig[:16])
		// }
	}

	return respBuf, nil
}
